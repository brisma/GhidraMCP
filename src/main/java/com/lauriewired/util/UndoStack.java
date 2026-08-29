package com.lauriewired.util;

import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Stepping a program's undo and redo stacks.
 *
 * Every write here already names the session that made it -- transactions are
 * recorded as "Create Function [a1b2c3]" precisely so a database can say who
 * acted. Undo is where that record stops being an audit trail and starts being
 * useful: a session that has just done something wrong can take it back
 * without a human in the GUI.
 *
 * It is also the most dangerous thing in this codebase, which is why the
 * report is as detailed as it is. The undo stack is SHARED -- with other
 * sessions holding the same program, and with the person sitting in front of
 * Ghidra. Undoing blind takes back whatever happened to be last, which may be
 * an hour of somebody else's work and will not look any different afterwards.
 * So the names come back with every step, and dry_run exists to look first.
 */
public final class UndoStack {

	/** How many stack entries to list back to the caller. */
	private static final int LISTED = 10;

	private UndoStack() {
	}

	/**
	 * Steps the stack, or describes what stepping it would do.
	 *
	 * @param program the program to step
	 * @param undo    true to undo, false to redo
	 * @param count   how many entries to take back
	 * @param dryRun  report only, change nothing
	 * @return what happened, or would have
	 */
	public static String step(Program program, boolean undo, int count, boolean dryRun) {
		final AtomicReference<String> result = new AtomicReference<>();
		final String verb = undo ? "undo" : "redo";
		try {
			SwingUtilities.invokeAndWait(() -> {
				List<String> pending = undo
						? program.getAllUndoNames()
						: program.getAllRedoNames();

				if (pending.isEmpty()) {
					result.set("Nothing to " + verb);
					return;
				}

				if (dryRun) {
					result.set(describe(verb, pending, count));
					return;
				}

				List<String> done = new ArrayList<>();
				try {
					for (int i = 0; i < count; i++) {
						if (undo ? !program.canUndo() : !program.canRedo()) {
							break;
						}
						// Read the name BEFORE stepping. Afterwards it has
						// moved to the other stack, and the caller would be
						// told the wrong thing had been taken back.
						String name = undo ? program.getUndoName() : program.getRedoName();
						if (undo) {
							program.undo();
						} else {
							program.redo();
						}
						done.add(name);
					}
				} catch (Exception e) {
					result.set("Error: " + verb + " failed after " + done.size()
							+ " step" + (done.size() == 1 ? "" : "s") + ": " + e.getMessage());
					return;
				}

				if (done.isEmpty()) {
					result.set("Nothing to " + verb);
					return;
				}
				StringBuilder sb = new StringBuilder();
				sb.append(undo ? "Undid " : "Redid ").append(done.size()).append(":\n");
				for (String name : done) {
					sb.append("  ").append(name).append("\n");
				}
				List<String> left = undo ? program.getAllUndoNames() : program.getAllRedoNames();
				sb.append(left.size()).append(" left to ").append(verb);
				result.set(sb.toString());
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: failed to " + verb + " on the Swing thread: " + e.getMessage();
		}
		return result.get();
	}

	/**
	 * What stepping would take back, without taking anything back.
	 *
	 * @param verb    "undo" or "redo"
	 * @param pending the stack, nearest first
	 * @param count   how many the caller asked for
	 * @return the report
	 */
	private static String describe(String verb, List<String> pending, int count) {
		StringBuilder sb = new StringBuilder();
		sb.append("Would ").append(verb).append(" ")
				.append(Math.min(count, pending.size()))
				.append(" of ").append(pending.size()).append(":\n");
		for (int i = 0; i < pending.size() && i < LISTED; i++) {
			sb.append(i < count ? "  -> " : "     ").append(pending.get(i)).append("\n");
		}
		if (pending.size() > LISTED) {
			sb.append("     ... and ").append(pending.size() - LISTED).append(" more\n");
		}
		return sb.append("Nothing was changed (dry_run).").toString();
	}
}
