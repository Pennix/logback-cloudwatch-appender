package net.pennix.logback.appender;

import static java.lang.String.format;
import static java.lang.String.join;
import static java.net.http.HttpClient.Redirect.ALWAYS;
import static java.net.http.HttpRequest.newBuilder;
import static java.net.http.HttpRequest.BodyPublishers.ofString;
import static java.net.http.HttpResponse.BodyHandlers.ofString;
import static java.net.http.HttpResponse.BodySubscribers.mapping;
import static java.net.http.HttpResponse.BodySubscribers.ofByteArray;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Instant.now;
import static java.time.ZoneOffset.UTC;
import static java.time.format.DateTimeFormatter.ofPattern;
import static java.util.stream.Collectors.joining;
import static javax.json.Json.createObjectBuilder;
import static javax.json.Json.createReader;
import static javax.json.stream.JsonCollectors.toJsonArray;
import static lombok.AccessLevel.PACKAGE;
import static net.pennix.logback.appender.KeyHolder.ALGORITHM;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpResponse.ResponseInfo;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.spi.ContextAwareBase;
import lombok.Setter;
import lombok.SneakyThrows;

public class CloudWatchLogsWorker extends ContextAwareBase implements Runnable {

	private static final DateTimeFormatter DTF_DATE = ofPattern("yyyyMMdd").withZone(UTC);

	private static final DateTimeFormatter DTF_TIMESTAMP = ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(UTC);

	private static final String AUTHORIZATION_TPL = "%s Credential=%s, SignedHeaders=%s, Signature=%s";

	private static final HttpClient client = HttpClient.newBuilder().followRedirects(ALWAYS).build();

	private static final String VERSION = "20140328";

	private static final String TARGET = "Logs_" + VERSION + ".%s";

	private static final String service = "logs";

	private static final char[] HEX = "0123456789abcdef".toCharArray();

	public static final String EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	@Setter(PACKAGE)
	private BlockingQueue<ILoggingEvent> blockingQueue;

	@Setter
	private String accessKeyId;

	@Setter
	private String secretAccessKey;

	/**
	 * {@link https://docs.aws.amazon.com/general/latest/gr/cwl_region.html }
	 */
	@Setter
	private String region;

	@Setter
	private String logGroup;

	@Setter
	private String logStream;

	@Setter
	private PatternLayout layout;

	private URI uri;

	private KeyHolder keyHolder;

	private volatile String nextToken;

	@Override
	public void run(
	) {
		region = region.toLowerCase();
		var endpoint = format("https://logs.%s.amazonaws.com%s/", region, region.startsWith("cn-") ? ".cn" : "");
		uri = URI.create(endpoint);

		layout.setContext(context);
		layout.start();

		keyHolder = new KeyHolder(service, region, secretAccessKey);

		try {
			for (int i = 0; i < 100; ++i)
				try {
					createLogGroup();
					nextToken = nextToken();
					break;
				} catch (IOException e) {
					Thread.sleep(500);
				}
		} catch (InterruptedException e) {
			return;
		}

		var list = new LinkedList<ILoggingEvent>();
		while (!Thread.interrupted()) {
			int count = blockingQueue.drainTo(list, 10000);
			if (count <= 0)
				continue;

			try {
				doPutEvents(list);
			} catch (IOException e) {
				addError(e.toString(), e);
			} catch (InterruptedException e) {
				break;
			}

			list.clear();
		}

		if (!blockingQueue.isEmpty()) {
			try {
				doPutEvents(blockingQueue);
			} catch (IOException | InterruptedException e) {
				addError(e.toString(), e);
			}
		}
	}

	private void doPutEvents(
			Collection<ILoggingEvent> events
	) throws IOException, InterruptedException {

		//@formatter:off
		var json = createObjectBuilder()
				.add("logGroupName", logGroup)
				.add("logStreamName", logStream)
				.add("logEvents", events.stream()
						.sorted((e1, e2) -> (int) (e1.getTimeStamp() - e2.getTimeStamp()))
						.map(event -> createObjectBuilder()
								.add("message", layout.doLayout(event))
								.add("timestamp", event.getTimeStamp())
								.build()
						).collect(toJsonArray())
				);
		//@formatter:on

		addInfo(format("%d events to push to %s", events.size(), logStream));
		addInfo(format("Next token: %s", nextToken));
		if (nextToken != null)
			json.add("sequenceToken", nextToken);
		String body = json.build().toString();

		var contentSHA256 = hashSHA256(body);
		var now = now();

		var headers = getHeaders(now, "POST", "PutLogEvents", contentSHA256);
		headers.put("Content-Type", "application/x-amz-json-1.1");
		headers.put("Accept", "application/json");

		Builder builder = newBuilder(uri).POST(ofString(body));
		headers.forEach(builder::header);

		var response = request(builder.build(), this::ofJson);
		if (response.statusCode() >= 400)
			addError(response.body().toString());
		if (response.body().containsKey("nextSequenceToken"))
			nextToken = response.body().getString("nextSequenceToken");
	}

	private void createLogGroup(
	) throws IOException, InterruptedException {
		var json = createObjectBuilder();
		json.add("logGroupName", logGroup);
		var body = json.build().toString();

		var contentSHA256 = hashSHA256(body);
		var now = now();

		var headers = getHeaders(now, "POST", "CreateLogGroup", contentSHA256);
		headers.put("Content-Type", "application/x-amz-json-1.1");
		headers.put("Accept", "application/json");

		Builder builder = newBuilder(uri).POST(ofString(body));
		headers.forEach(builder::header);

		var response = request(builder.build(), ofString());
		if (response.statusCode() >= 400) {
			try (var reader = createReader(new StringReader(response.body()))) {
				var type = reader.readObject().getString("__type", null);
				if (!"ResourceAlreadyExistsException".equalsIgnoreCase(type))
					addError(format("%d %s", response.statusCode(), type));
			}
		}
	}

	private String nextToken(
	) throws IOException, InterruptedException {
		var json = createObjectBuilder();
		json.add("logGroupName", logGroup);
		json.add("logStreamNamePrefix", logStream);
		String body = json.build().toString();

		var contentSHA256 = hashSHA256(body);
		var now = now();

		var headers = getHeaders(now, "POST", "DescribeLogStreams", contentSHA256);
		headers.put("Content-Type", "application/x-amz-json-1.1");
		headers.put("Accept", "application/json");

		Builder builder = newBuilder(uri).POST(ofString(body));
		headers.forEach(builder::header);
		var response = request(builder.build(), this::ofJson);

		var logStreams = response.body().getJsonArray("logStreams");
		if (logStreams != null && logStreams.size() > 0) {
			var found = logStreams.stream().map(JsonObject.class::cast).filter(stream -> logStream.equals(stream.getString("logStreamName"))).findFirst();
			if (found.isPresent())
				return found.get().getString("uploadSequenceToken", null);
		}
		createLogStream();
		return null;
	}

	private void createLogStream(
	) throws IOException, InterruptedException {
		var json = createObjectBuilder();
		json.add("logGroupName", logGroup);
		json.add("logStreamName", logStream);
		var body = json.build().toString();

		var contentSHA256 = hashSHA256(body);
		var now = now();

		var headers = getHeaders(now, "POST", "CreateLogStream", contentSHA256);
		//headers.put("Connection", "Keep-Alive");
		headers.put("Content-Type", "application/x-amz-json-1.1");
		//headers.put("Content-Length", valueOf(body.getBytes(UTF_8).length));
		headers.put("Accept", "application/json");

		Builder builder = newBuilder(uri).POST(ofString(body));
		headers.forEach(builder::header);

		var response = request(builder.build(), ofString());
		if (response.statusCode() >= 400) {
			try (var reader = createReader(new StringReader(response.body()))) {
				var type = reader.readObject().getString("__type", null);
				if (!"ResourceAlreadyExistsException".equalsIgnoreCase(type))
					addError(format("%d %s", response.statusCode(), type));
			}
		}
	}

	private <T> HttpResponse<T> request(
			HttpRequest request,
			BodyHandler<T> handler
	) throws IOException, InterruptedException {

		addInfo(format("%s to %s", request.method(), request.uri().toString()));
		request.headers().map().forEach((key, values) -> addInfo(format("Request Header [%s]: %s", key, join(",", values))));

		HttpResponse<T> response = client.send(request, handler);

		//addInfo(format("HTTP Version: %s", response.version()));
		addInfo(format("Response Status: %d", response.statusCode()));
		response.headers().map().forEach((key, values) -> addInfo(format("Response Header [%s]: %s", key, join(",", values))));

		return response;
	}

	private Map<String, String> getHeaders(
			Instant now,
			String method,
			String action,
			String contentSHA256
	) {
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Host", uri.getHost());
		//headers.put("X-Amz-Content-sha256", contentSHA256);
		headers.put("X-Amz-Date", DTF_TIMESTAMP.format(now));
		headers.put("X-Amz-Target", format(TARGET, action));

		String authorization = this.getAuthorization(now, method, uri.getPath(), headers, contentSHA256);
		headers.put("Authorization", authorization);

		headers.remove("Host"); // not allowed to set forcibly
		return headers;
	}

	private String getAuthorization(
			Instant now,
			String method,
			String uri,
			Map<String, String> headers,
			String contentSHA256
	) {
		Map<String, String> map = this.canonicalHeaders(headers);

		String canonicalURI = "/";
		String canonicalQueryString = "";
		String canonicalHeaders = map.entrySet().stream().map(entry -> join(":", entry.getKey(), entry.getValue())).collect(joining("\n", "", "\n"));
		String signedHeaders = join(";", map.keySet());

		String canonicalRequest = join("\n", method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, contentSHA256);

		String algorithm = "AWS4-HMAC-SHA256";
		String requestDateTime = DTF_TIMESTAMP.format(now);
		String credentialScope = join("/", DTF_DATE.format(now), region, service, "aws4_request");
		String hashedCanonicalRequest = hashSHA256(canonicalRequest);

		String stringToSign = join("\n", algorithm, requestDateTime, credentialScope, hashedCanonicalRequest);

		String signature = this.signature(now, stringToSign);
		String credential = join("/", accessKeyId, credentialScope);
		return format(AUTHORIZATION_TPL, algorithm, credential, signedHeaders, signature);
	}

	@SneakyThrows({ NoSuchAlgorithmException.class, InvalidKeyException.class })
	private String signature(
			Instant now,
			String stringToSign
	) {
		byte[] key = keyHolder.getKey(DTF_DATE.format(now));

		Mac mac = Mac.getInstance(ALGORITHM);
		mac.init(new SecretKeySpec(key, ALGORITHM));
		byte[] signature = mac.doFinal(stringToSign.getBytes(UTF_8));

		return hexEncode(signature);
	}

	private Map<String, String> canonicalHeaders(
			Map<String, String> headers
	) {
		Map<String, String> map = new TreeMap<>();
		if (headers != null && headers.size() > 0)
			headers.forEach((key, value) -> map.put(key.toLowerCase(), value.trim()));
		//headers.keySet().forEach(key -> map.put(key.toLowerCase(), headers.get(key).trim()));
		return map;
	}

	private BodySubscriber<JsonObject> ofJson(
			ResponseInfo responseInfo
	) {
		return mapping(ofByteArray(), bytes -> createReader(new ByteArrayInputStream(bytes)).readObject());
	}

	@SneakyThrows(NoSuchAlgorithmException.class)
	private static String hashSHA256(
			String string
	) {
		if (string == null || string.isEmpty())
			return EMPTY_SHA256;

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(string.getBytes(UTF_8));
		byte[] bytes = digest.digest();
		return hexEncode(bytes);
	}

	private static String hexEncode(
			byte[] bytes
	) {
		final int nBytes = bytes.length;
		char[] result = new char[2 * nBytes];
		int j = 0;
		for (byte aByte : bytes) {
			// Char for top 4 bits
			result[j++] = HEX[(0xF0 & aByte) >>> 4];
			// Bottom 4
			result[j++] = HEX[(0x0F & aByte)];
		}
		return new String(result);
	}
}
