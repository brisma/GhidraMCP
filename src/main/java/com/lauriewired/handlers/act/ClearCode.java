package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parseLongOrDefault;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for clearing code back to undefined bytes -- Ghidra's C key.
 *
 * The counterpart to {@link Disassemble}, and the reason that one is safe to
 * use: without a way to undo it, a disassembly started in the wrong mode or at
 * the wrong offset was permanent as far as the MCP was concerned, and had to
 * be repaired by a human in the GUI.
 *
 * Clearing a range that a function is defined over leaves that function with a
 * body full of holes, so a range overlapping one is refused and the functions
 * are named. Passing force=true does it anyway, which is what you want when
 * you are deliberately taking a misidentified function apart.
 */
public final class ClearCode extends Handler {
	/** Most functions named in a refusal before the list is cut short. */
	private static final int MAX_NAMED = 10;

	/**
	 * Constructor for the ClearCode handler
	 *
	 * @param tool the PluginTool instance
	 */
	public ClearCode(PluginTool tool) {
		super(tool, "/clear_code");
	}

	/**
	 * Handle the HTTP request to clear code units over a range.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String endStr = params.get("end");
		long length = parseLongOrDefault(params.get("length"), 0);
		boolean clearContext = Boolean.parseBoolean(params.get("clear_context"));
		boolean force = Boolean.parseBoolean(params.get("force"));

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		if (length < 0) {
			sendResponse(exchange, "Error: length cannot be negative");
			return;
		}
		sendResponse(exchange, clearCode(address, endStr, length, clearContext, force));
	}

	/**
	 * Clears the code units over the requested range.
	 *
	 * @param addressStr    where to start
	 * @param endStr        last address, or null to use the length
	 * @param length        bytes to clear, or 0 to clear only the code unit at
	 *                      the start address
	 * @param clearContext  also clear the processor context (TMode, ISA_MODE)
	 * @param force         clear even where functions are defined
	 * @return what was done
	 */
	private String clearCode(String addressStr, String endStr, long length,
			boolean clearContext, boolean force) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Address start = parseAddress(program, addressStr);
		if (start == null)
			return "Error: invalid address " + addressStr;

		Address end;
		if (endStr != null && !endStr.isEmpty()) {
			end = parseAddress(program, endStr);
			if (end == null)
				return "Error: invalid end address " + endStr;
			if (end.compareTo(start) < 0)
				return "Error: end " + endStr + " is before address " + addressStr;
		} else if (length > 0) {
			try {
				end = start.addNoWrap(length - 1);
			} catch (Exception e) {
				return "Error: length runs past the end of the address space";
			}
		} else {
			// No extent given: clear exactly the one code unit that is here,
			// which is what pressing C on a single line does.
			var cu = program.getListing().getCodeUnitContaining(start);
			if (cu == null)
				return "Nothing defined at " + addressStr;
			start = cu.getMinAddress();
			end = cu.getMaxAddress();
		}

		final Address from = start;
		final Address to = end;

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				// The overlap check happens on the Swing thread, in the same
				// turn as the clear it guards. Deciding it on the HTTP thread
				// and then clearing here leaves a window in which a function
				// can appear over the range between the two -- which is
				// precisely the case the check exists to catch.
				List<String> overlapping = functionsOver(program, from, to);
				if (!overlapping.isEmpty() && !force) {
					result.set(refusal(from, to, overlapping));
					return;
				}

				int txId = program.startTransaction(tx("Clear Code"));
				boolean success = false;
				try {
					program.getListing().clearCodeUnits(from, to, clearContext);
					StringBuilder sb = new StringBuilder();
					sb.append("Cleared ").append(to.subtract(from) + 1).append(" bytes, ")
							.append(from).append(" - ").append(to);
					if (clearContext) {
						sb.append(", including processor context");
					}
					if (!overlapping.isEmpty()) {
						sb.append("\nForced over ").append(overlapping.size())
								.append(overlapping.size() == 1 ? " function" : " functions")
								.append("; their bodies now cover undefined bytes.");
					}
					result.set(sb.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to clear code: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute clear code on Swing thread: " + e.getMessage();
		}
		return result.get();
	}

	/**
	 * The message sent when a range is covered by functions and force is off.
	 *
	 * @param from        first address of the range
	 * @param to          last address of the range
	 * @param overlapping the functions in the way
	 * @return a refusal naming them
	 */
	private static String refusal(Address from, Address to, List<String> overlapping) {
		StringBuilder sb = new StringBuilder();
		sb.append("Refused: ").append(from).append(" - ").append(to)
				.append(" is covered by ").append(overlapping.size())
				.append(overlapping.size() == 1 ? " function" : " functions")
				.append(", and clearing would leave ")
				.append(overlapping.size() == 1 ? "it" : "them")
				.append(" defined over bytes that are no longer code:\n");
		for (int i = 0; i < overlapping.size() && i < MAX_NAMED; i++) {
			sb.append("  ").append(overlapping.get(i)).append("\n");
		}
		if (overlapping.size() > MAX_NAMED) {
			sb.append("  ... and ").append(overlapping.size() - MAX_NAMED).append(" more\n");
		}
		return sb.append("Nothing was done. Delete those functions first, "
				+ "or pass force=true if you mean to.").toString();
	}

	/**
	 * Functions whose bodies touch the range at all.
	 *
	 * @param program the program
	 * @param from    first address of the range
	 * @param to      last address of the range
	 * @return "name @ entry" for each overlapping function
	 */
	private static List<String> functionsOver(Program program, Address from, Address to) {
		List<String> names = new ArrayList<>();
		AddressSet range = new AddressSet(from, to);
		// getFunctionsOverlapping, not getFunctions: the latter iterates
		// functions whose ENTRY POINT is in the set, which misses the case that
		// matters most -- a range in the middle of a large function, whose
		// entry is far above it.
		Iterator<Function> it = program.getFunctionManager().getFunctionsOverlapping(range);
		while (it.hasNext()) {
			Function f = it.next();
			names.add(f.getName() + " @ " + f.getEntryPoint());
		}
		return names;
	}
}
