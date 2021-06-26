package net.pennix.logback;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

class AppTest {

	private Logger logger = LoggerFactory.getLogger(AppTest.class);

	@BeforeAll
	static void setUpBeforeClass(
	) throws Exception {
	}

	@AfterAll
	static void tearDownAfterClass(
	) throws Exception {
	}

	@BeforeEach
	void setUp(
	) throws Exception {
	}

	@AfterEach
	void tearDown(
	) throws Exception {
	}

	@Test
	void test(
	) throws InterruptedException {
		MDC.put("ip", "127.0.0.1");
		MDC.put("user", "alice");

		for (int i = 0; i < 10; ++i) {
			logger.info("Test event {}", i);
		}
		Thread.sleep(10000);
		for (int i = 10; i < 20; ++i) {
			logger.info("Test event {}", i);
		}
		Thread.sleep(10000);
	}
}
