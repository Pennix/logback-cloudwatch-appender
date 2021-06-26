package net.pennix.logback.appender;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import ch.qos.logback.core.util.InterruptUtil;
import lombok.Setter;

public class CloudWatchLogsAppender extends UnsynchronizedAppenderBase<ILoggingEvent> {

	/**
	 * The default buffer size.
	 */
	public static final int DEFAULT_QUEUE_SIZE = 1024;

	@Setter
	int queueSize = DEFAULT_QUEUE_SIZE;

	/**
	 * The default maximum queue flush time allowed during appender stop. If the 
	 * worker takes longer than this time it will exit, discarding any remaining 
	 * items in the queue
	 */
	public static final int DEFAULT_MAX_FLUSH_TIME = 1000;

	@Setter
	int maxFlushTime = DEFAULT_MAX_FLUSH_TIME;

	@Setter
	boolean prepareForDeferredProcessing = false;

	BlockingQueue<ILoggingEvent> blockingQueue;

	@Setter
	CloudWatchLogsWorker worker;

	Thread workerThread;

	@Override
	public void start(
	) {
		if (isStarted())
			return;
		if (queueSize < 1) {
			addError("Invalid queue size [" + queueSize + "]");
			return;
		}
		blockingQueue = new ArrayBlockingQueue<ILoggingEvent>(queueSize);
		worker.setBlockingQueue(blockingQueue);

		workerThread = new Thread(worker);
		workerThread.setDaemon(true);
		workerThread.setName("CloudwatchLogsAppender-Worker-" + getName());
		// make sure this instance is marked as "started" before staring the worker Thread
		super.start();
		workerThread.start();
	}

	@Override
	public void stop(
	) {
		if (!isStarted())
			return;

		super.stop();

		if (workerThread == null)
			return;

		// interrupt the worker thread so that it can terminate. Note that the interruption can be consumed
		// by sub-appenders
		workerThread.interrupt();

		InterruptUtil interruptUtil = new InterruptUtil(context);

		try {
			interruptUtil.maskInterruptFlag();

			workerThread.join(maxFlushTime);

			// check to see if the thread ended and if not add a warning message
			if (workerThread.isAlive()) {
				addWarn("Max queue flush timeout (" + maxFlushTime + " ms) exceeded. Approximately " + blockingQueue.size() + " queued events were possibly discarded.");
			} else {
				addInfo("Queue flush finished successfully within timeout.");
			}

		} catch (InterruptedException e) {
			int remaining = blockingQueue.size();
			addError("Failed to join worker thread. " + remaining + " queued events may be discarded.", e);
		} finally {
			interruptUtil.unmaskInterruptFlag();
		}
	}

	@Override
	protected void append(
			ILoggingEvent eventObject
	) {
		if (prepareForDeferredProcessing)
			eventObject.prepareForDeferredProcessing();
		blockingQueue.offer(eventObject);
	}
}
