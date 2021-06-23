package net.pennix.logback.appender;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@RequiredArgsConstructor
public class KeyHolder {

	public static final String ALGORITHM = "HmacSHA256";

	private final String service;

	private final String region;

	private final String secretAccessKey;

	private volatile String keyDate = null;

	private volatile byte[] key = null;

	public byte[] getKey(
			String date
	) {
		if (!date.equals(keyDate))
			synchronized (this) {
				if (!date.equals(keyDate)) {
					key = createKey(date);
					keyDate = date;
				}
			}
		return key;
	}

	@SneakyThrows({ NoSuchAlgorithmException.class, InvalidKeyException.class })
	private byte[] createKey(
			String date
	) {
		Mac mac = Mac.getInstance(ALGORITHM);
		mac.init(new SecretKeySpec(("AWS4" + secretAccessKey).getBytes(UTF_8), ALGORITHM));
		byte[] dateKey = mac.doFinal(date.getBytes(UTF_8));

		mac.reset();
		mac.init(new SecretKeySpec(dateKey, ALGORITHM));
		byte[] dateRegionKey = mac.doFinal(region.getBytes(UTF_8));

		mac.reset();
		mac.init(new SecretKeySpec(dateRegionKey, ALGORITHM));
		byte[] dateRegionServiceKey = mac.doFinal(service.getBytes(UTF_8));

		mac.reset();
		mac.init(new SecretKeySpec(dateRegionServiceKey, ALGORITHM));
		return mac.doFinal("aws4_request".getBytes());
	}
}
