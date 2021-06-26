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
		<!-- NOTE: change this to the most recent release version from the repo -->
		<version>1.0.1</version>
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

**NOTE: DO NOT use the same log stream in multiple appenders or multiple application instances, this is a limit by aws**

``` xml
<appender name="CLOUDWATCH" class="net.pennix.logback.appender.CloudWatchLogsAppender">
	<!-- queue size to hold events before put to cloudwatch -->
	<queueSize>1024</queueSize>
	<!-- time to wait for remaining events to be cleared/sent before application quit -->
	<maxFlushTime>1000</maxFlushTime>
	<!-- set to true if you need THREAD NAME or MDC PROPERTIES in log message, would slightly decrease performance to do this -->
	<prepareForDeferredProcessing>false</prepareForDeferredProcessing>
	<worker>
		<accessKeyId>${your.aws.access.key.id}</accessKeyId>
		<secretAccessKey>${your.aws.secret.access.key}</secretAccessKey>
		<region>${target.region.of.cloudwatch.service}</region>
		<logGroup>${your.log.group.name}</logGroup>
		<logStream>${your.log.stream.name}</logStream>
		<!-- logs are put in batch (10000 events max according to aws specification),
		so we can sleep a little while before draining the queue and doing api request,
		lower value would raise request frequency and cpu usage,
		set to 0 to disable sleep,
		which is not recommended unless the logs are really that much -->
		<sleepTimeBetweenPuts>500</sleepTimeBetweenPuts>
		<layout>
			<pattern>%1.-1level [%thread] %logger - %msg%n</pattern>
		</layout>
	</worker>
</appender>
```

See the example [logback-test.xml file](src/main/resources/logback-test.xml).

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

## v1.0.1

* allow to enable/disable **prepareForDeferredProcessing**
* sleep between puts to reduce cpu usage
* removed some *addInfo* to improve performance
