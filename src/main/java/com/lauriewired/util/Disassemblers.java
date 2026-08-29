package com.lauriewired.util;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.disassemble.MipsDisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Building the disassembly command that Ghidra's D key builds.
 *
 * The second argument to {@link DisassembleCommand} is the set of addresses
 * disassembly is ALLOWED to touch, not the place to start. Passing a one-byte
 * set there -- which is what create_function did -- stops the disassembler
 * after a single instruction: the block terminates the moment flow reaches
 * addr+1, which is outside the set. The function that gets defined on top of
 * it is one instruction long, and it is reported as created.
 *
 * So: null means follow the flow as far as it goes, and a bounded set means a
 * deliberate limit the caller asked for. Nothing in between.
 */
public final class Disassemblers {

	/** Which instruction set to decode as. */
	public enum Mode {
		/** Whatever the program context already says. Ghidra's plain D. */
		AUTO,
		/** ARM, 4-byte aligned, TMode cleared. */
		ARM,
		/** THUMB, 2-byte aligned, TMode set. */
		THUMB,
		/** MIPS32, ISA_MODE cleared. */
		MIPS,
		/** MIPS16, ISA_MODE set. */
		MIPS16
	}

	private Disassemblers() {
	}

	/**
	 * Reads a mode name, tolerating case and the empty string.
	 *
	 * @param raw the caller's mode, or null
	 * @return the mode, or null if the name is not one we know
	 */
	public static Mode parseMode(String raw) {
		if (raw == null || raw.trim().isEmpty()) {
			return Mode.AUTO;
		}
		try {
			return Mode.valueOf(raw.trim().toUpperCase());
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	/** The mode names a caller may use, for error messages. */
	public static String modeNames() {
		StringBuilder sb = new StringBuilder();
		for (Mode m : Mode.values()) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(m.name().toLowerCase());
		}
		return sb.toString();
	}

	/**
	 * Why this program cannot be disassembled in this mode, or null if it can.
	 *
	 * ArmDisassembleCommand returns false with no status message when asked
	 * for THUMB on a language that has no TMode register, which reaches the
	 * caller as a bare "disassembly failed". Saying which processor is loaded
	 * turns that into something actionable.
	 *
	 * @param program the program
	 * @param mode    the requested mode
	 * @return a sentence explaining the refusal, or null if the mode is usable
	 */
	public static String unsupported(Program program, Mode mode) {
		String processor = program.getLanguage().getProcessor().toString();
		switch (mode) {
			case THUMB:
				if (program.getProgramContext().getRegister("TMode") == null) {
					return "THUMB needs a TMode register, which " + processor
							+ " does not have";
				}
				return null;
			case ARM:
				if (program.getProgramContext().getRegister("TMode") == null) {
					return "ARM mode needs a TMode register, which " + processor
							+ " does not have";
				}
				return null;
			case MIPS16:
				if (program.getProgramContext().getRegister("ISA_MODE") == null) {
					return "MIPS16 needs an ISA_MODE register, which " + processor
							+ " does not have";
				}
				return null;
			case MIPS:
				if (program.getProgramContext().getRegister("ISA_MODE") == null) {
					return "MIPS mode needs an ISA_MODE register, which " + processor
							+ " does not have";
				}
				return null;
			case AUTO:
			default:
				return null;
		}
	}

	/**
	 * The command Ghidra's D key would build for this address.
	 *
	 * @param at         where to start
	 * @param restricted addresses disassembly may touch, or null for no limit.
	 *                   NULL IS THE NORMAL CASE -- a non-null set here is a
	 *                   ceiling the caller asked for, not a starting point.
	 * @param mode       which instruction set to decode as
	 * @return a command ready to apply
	 */
	public static DisassembleCommand command(Address at, AddressSetView restricted, Mode mode) {
		switch (mode) {
			case ARM:
				return new ArmDisassembleCommand(at, restricted, false);
			case THUMB:
				return new ArmDisassembleCommand(at, restricted, true);
			case MIPS:
				return new MipsDisassembleCommand(at, restricted, false);
			case MIPS16:
				return new MipsDisassembleCommand(at, restricted, true);
			case AUTO:
			default:
				return new DisassembleCommand(at, restricted, true);
		}
	}
}
