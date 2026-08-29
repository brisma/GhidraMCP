package com.lauriewired;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * A rule, not a habit: a decompiler is opened in one place and always closed.
 *
 * DecompInterface.openProgram starts a native decompiler process. From the
 * first version of this plugin until now, four handlers each opened their own
 * and not one of them ever called dispose(), so a session leaked a process per
 * decompilation, per variable rename and per local-type change -- and the two
 * handlers that searched for a function by name opened theirs BEFORE the
 * search, so even a misspelled name cost one.
 *
 * The pairing is not something to remember at each new call site, so it is
 * checked here instead: construction lives in Decompilers, and every use of
 * it must dispose.
 */
public class DecompilerDisposalRuleTest {

	/** Where a decompiler may legitimately be constructed. */
	private static final String FACTORY = "Decompilers.java";

	private static List<Path> sources() throws IOException {
		try (Stream<Path> files = Files.walk(Paths.get("src/main/java"))) {
			return files.filter(f -> f.toString().endsWith(".java")).sorted().toList();
		}
	}

	@Test
	public void aDecompilerIsOnlyEverConstructedInOnePlace() throws IOException {
		List<String> offenders = new ArrayList<>();
		for (Path p : sources()) {
			if (p.getFileName().toString().equals(FACTORY)) {
				continue;
			}
			int n = 0;
			for (String line : Files.readAllLines(p)) {
				n++;
				// Skip prose: the rule is about code, and the comments
				// explaining the rule necessarily quote it.
				String code = line.trim();
				if (code.startsWith("*") || code.startsWith("//")) {
					continue;
				}
				if (code.contains("new DecompInterface(")) {
					offenders.add(p.getFileName() + ":" + n + " " + code);
				}
			}
		}
		assertEquals("open a decompiler with Decompilers.open(program) instead",
				Collections.emptyList(), offenders);
	}

	@Test
	public void everyFileThatOpensADecompilerAlsoDisposesIt() throws IOException {
		List<String> offenders = new ArrayList<>();
		for (Path p : sources()) {
			if (p.getFileName().toString().equals(FACTORY)) {
				continue;
			}
			String body = Files.readString(p);
			if (body.contains("Decompilers.open(") && !body.contains(".dispose()")) {
				offenders.add(p.getFileName().toString());
			}
		}
		assertEquals("a decompiler must be disposed on every path out",
				Collections.emptyList(), offenders);
	}
}
