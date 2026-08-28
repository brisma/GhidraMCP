package com.lauriewired;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * A rule, not a habit: nothing may open a Ghidra transaction without naming the
 * session that asked for it. Enforced here so a handler written next year
 * cannot quietly go back to "Create Function".
 */
public class TransactionNamingRuleTest {

	private static List<String> offendingLines(String call) throws IOException {
		List<String> bad = new ArrayList<>();
		try (Stream<Path> files = Files.walk(Paths.get("src/main/java"))) {
			for (Path p : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
				// The name reaching GhidraUtils has already been decorated by
				// the handler that called it; the rule below covers that call.
				if (p.getFileName().toString().equals("GhidraUtils.java")) {
					continue;
				}
				int n = 0;
				for (String line : Files.readAllLines(p)) {
					n++;
					if (line.contains(call) && !line.contains("tx(")) {
						bad.add(p.getFileName() + ":" + n + " " + line.trim());
					}
				}
			}
		}
		return bad;
	}

	@Test
	public void noTransactionIsOpenedWithoutNamingTheSession() throws IOException {
		assertEquals(Collections.emptyList(), offendingLines("startTransaction("));
	}

	@Test
	public void noCommentIsWrittenWithoutNamingTheSession() throws IOException {
		assertEquals(Collections.emptyList(), offendingLines("setCommentAtAddress("));
	}
}
