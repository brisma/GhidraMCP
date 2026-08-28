package com.lauriewired;

import org.junit.Test;
import static org.junit.Assert.*;

import java.nio.file.*;

/**
 * A guard, not a discovery: Handler carries the calling session in a plain
 * field, which is only safe while each server dispatches one request at a time.
 * Giving the HTTP server an executor would make two requests share that field.
 * If you need concurrency, pass the session down instead of storing it.
 */
public class ServerIsSerialTest {

	@Test
	public void theHttpServerDispatchesOneRequestAtATime() throws Exception {
		String src = Files.readString(
				Paths.get("src/main/java/com/lauriewired/GhidraMCPPlugin.java"));
		assertTrue("the server must keep its default (single-threaded) executor",
				src.contains("server.setExecutor(null)"));
	}
}
