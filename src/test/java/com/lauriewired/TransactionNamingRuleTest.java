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
				List<String> lines = Files.readAllLines(p);
				for (int i = 0; i < lines.size(); i++) {
					if (!lines.get(i).contains(call)) {
						continue;
					}
					// Read to the end of the STATEMENT, not the end of the
					// line. A call wrapped across two lines put tx() on the
					// second one and was reported as an offender even though
					// it named the session correctly -- the rule was reading
					// formatting rather than code.
					if (!statementAt(lines, i).contains("tx(")) {
						bad.add(p.getFileName() + ":" + (i + 1) + " " + lines.get(i).trim());
					}
				}
			}
		}
		return bad;
	}

	/** The whole statement beginning on line {@code i}, joined into one string. */
	private static String statementAt(List<String> lines, int i) {
		StringBuilder sb = new StringBuilder();
		for (int j = i; j < lines.size() && j < i + 8; j++) {
			sb.append(lines.get(j).trim()).append(' ');
			if (lines.get(j).contains(";")) {
				break;
			}
		}
		return sb.toString();
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
