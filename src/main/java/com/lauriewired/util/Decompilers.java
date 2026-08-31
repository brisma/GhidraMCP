package com.lauriewired.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Program;

import java.io.IOException;

/**
 * Opening a decompiler, and saying what went wrong when it will not open.
 *
 * <p>This exists because the four handlers that decompile each had the same two
 * faults, and both were expensive.
 *
 * <p><b>A native process per request, never released.</b> Every
 * {@code new DecompInterface()} that is not {@link DecompInterface#dispose()}d
 * leaves its {@code decompile} child process running for the life of the JVM.
 * On one long-lived Ghidra session that reached <b>328 orphaned processes</b>,
 * the oldest 47 hours old, all idle at 0.02 s of CPU. Every caller here must
 * dispose in a {@code finally}, which is what {@link #open} is shaped to make
 * natural.
 *
 * <p><b>And the reason a failure happened was thrown away.</b>
 * {@code openProgram} returns false and leaves its reason in
 * {@code getLastMessage()}; the handlers ignored the return value, and
 * {@code decompileFunction} then sees {@code program == null}, returns an empty
 * result <i>and clears the message first</i>. So the caller was told
 * "Decompilation failed" and the log said nothing at all. Diagnosing one such
 * failure took an hour of reading Ghidra's own source to work out that the
 * message had ever existed. Refusing at {@code open}, with the message
 * attached, is the whole point.
 */
public final class Decompilers {

	private Decompilers() {
	}

	/**
	 * A decompiler already open on {@code program}. The caller owns it and must
	 * {@link DecompInterface#dispose()} it in a {@code finally}.
	 *
	 * @param program the program to open
	 * @param options the options to set before opening, or null for the defaults
	 * @return an open DecompInterface
	 * @throws IOException if it would not open, carrying the decompiler's own words
	 */
	public static DecompInterface open(Program program, DecompileOptions options) throws IOException {
		DecompInterface decomp = new DecompInterface();
		if (options != null) {
			decomp.setOptions(options);
		}
		if (!decomp.openProgram(program)) {
			String why = decomp.getLastMessage();
			decomp.dispose();
			throw new IOException("the decompiler would not open this program: "
					+ (why == null || why.isEmpty() ? "it gave no reason" : why));
		}
		return decomp;
	}

	/**
	 * A decompiler open on {@code program} with the default options.
	 *
	 * @param program the program to open
	 * @return an open DecompInterface
	 * @throws IOException if it would not open, carrying the decompiler's own words
	 */
	public static DecompInterface open(Program program) throws IOException {
		return open(program, null);
	}

	/**
	 * Why a decompilation did not complete, in the decompiler's own words.
	 *
	 * @param result the results to report on, possibly null
	 * @return a message naming the reason, or saying that none was given
	 */
	public static String failure(DecompileResults result) {
		if (result == null) {
			return "Decompilation failed: no results at all";
		}
		String why = result.getErrorMessage();
		return "Decompilation failed" + (why == null || why.isEmpty() ? "" : ": " + why);
	}
}
