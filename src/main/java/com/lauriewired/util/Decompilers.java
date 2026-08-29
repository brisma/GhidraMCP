package com.lauriewired.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * The only place a decompiler is opened.
 *
 * {@link DecompInterface#openProgram} starts a native decompiler process, and
 * nothing in this project's history ever stopped one: every decompile, every
 * variable rename and every local-type change since the plugin was first
 * written leaked a process for the life of the Ghidra session. Four call sites
 * each opened their own, and only one of them bothered to set any options.
 *
 * Funnelling it through here makes the pairing checkable rather than
 * remembered -- see DecompilerDisposalRuleTest, which fails the build if
 * `new DecompInterface()` appears anywhere else.
 */
public final class Decompilers {

	/** Tool options category the plugin registers its settings under. */
	private static final String OPTION_CATEGORY = "GhidraMCP HTTP Server";

	/** Name of the decompile timeout option. */
	private static final String TIMEOUT_OPTION = "Decompile Timeout";

	/** Timeout used when the tool has no opinion. */
	public static final int DEFAULT_TIMEOUT_SECONDS = 30;

	private Decompilers() {
	}

	/**
	 * How long a decompilation may run, in seconds.
	 *
	 * The plugin has registered a "Decompile Timeout" option since it was
	 * written, stored it in a field, and never read it: all four call sites
	 * hardcoded 30. Reading it here is what makes the setting mean something.
	 *
	 * @param tool the plugin tool, or null
	 * @return the configured timeout, or {@link #DEFAULT_TIMEOUT_SECONDS}
	 */
	public static int timeoutSeconds(PluginTool tool) {
		if (tool == null) {
			return DEFAULT_TIMEOUT_SECONDS;
		}
		try {
			Options options = tool.getOptions(OPTION_CATEGORY);
			int configured = options.getInt(TIMEOUT_OPTION, DEFAULT_TIMEOUT_SECONDS);
			return configured > 0 ? configured : DEFAULT_TIMEOUT_SECONDS;
		} catch (Exception e) {
			return DEFAULT_TIMEOUT_SECONDS;
		}
	}

	/**
	 * Opens a decompiler against a program. The caller must dispose it.
	 *
	 * Always call this in a try/finally:
	 *
	 * <pre>
	 * DecompInterface decomp = Decompilers.open(program);
	 * try {
	 *     ...
	 * } finally {
	 *     decomp.dispose();
	 * }
	 * </pre>
	 *
	 * @param program the program to decompile against
	 * @return an open decompiler
	 * @throws IllegalStateException if the decompiler will not open
	 */
	public static DecompInterface open(Program program) {
		DecompInterface decomp = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.setRespectReadOnly(true);
		decomp.setOptions(options);
		if (!decomp.openProgram(program)) {
			String why = decomp.getLastMessage();
			decomp.dispose();
			throw new IllegalStateException("Could not open the decompiler"
					+ (why != null && !why.isEmpty() ? ": " + why : ""));
		}
		return decomp;
	}
}
