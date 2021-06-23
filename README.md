Logback appender for AWS CloudWatch logs
=========================================

# Background

This package provides a logback appender that writes log events to Cloudwatch logs.
There're many projects out there but I created this because I don't want to include aws sdk and that lots of dependencies just for logging.

* That said, the only dependency of this project is **JSR 374** json processing
* but it is using **java.net.http** to do http request, so you need at least java 11.

# Maven Configuration

``` xml
<dependencies>
	<dependency>
		<groupId>net.pennix</groupId>
		<artifactId>logback-cloudwatch-appender</artifactId>
		<!-- NOTE: change the version to the most recent release version from the repo -->
		<version>1.0.0</version>
		<scope>runtime</scope>
	</dependency>
</dependencies>
```

## Dependencies

The only dependency besides logback is **JSR 374** json processing, you don't have to include this manually.

``` xml
<dependency>
	<groupId>org.glassfish</groupId>
	<artifactId>javax.json</artifactId>
	<version>${javax.jsonp.version}</version>
	<scope>runtime</scope>
</dependency>
```

# logback.xml Configuration

Minimal logback appender configuration:

**DO NOT use the same log stream in multiple appenders**

``` xml
<appender name="CLOUDWATCH" class="net.pennix.logback.appender.CloudWatchLogsAppender">
	<queueSize>256</queueSize>
	<maxFlushTime>1000</maxFlushTime>
	<worker>
		<accessKeyId>${your.aws.access.key.id}</accessKeyId>
		<secretAccessKey>${your.aws.secret.access.key}</secretAccessKey>
		<region>${target.region.of.cloudwatch.service}</region>
		<logGroup>${your.log.group.name}</logGroup>
		<logStream>${your.log.stream.name}</logStream>
		<layout>
			<pattern>%1.-1level [%thread] %logger - %msg%n</pattern>
		</layout>
	</worker>
</appender>
```

See the example [logback-test.xml file](src/main/java/resources/logback-test.xml).

# IAM Permissions

``` json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

You should probably limit **Resource** to specific region/account/logGroup.

# ChangeLog Release Notes

Might add here if I ever change anything.
