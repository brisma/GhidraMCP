package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.lauriewired.util.Disassemblers;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parseLongOrDefault;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static com.lauriewired.util.ParseUtils.splitAddresses;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for turning undefined bytes into instructions -- Ghidra's D key.
 *
 * This is the primitive that was missing. create_function did a disassembly
 * on the way to defining a function, but there was no way to ask for only the
 * disassembly, and no way at all to reach bytes that should not become a
 * function: jump-table bodies, data misread as code that needs looking at
 * first, a THUMB stub inside an ARM region. The nearest thing on offer,
 * disassemble_function, is a reader -- despite the name it has never
 * disassembled anything, and it refuses any address that is not already
 * inside a function.
 *
 * Flow is followed as far as it goes unless the caller sets a length, which
 * is the only thing that may bound it.
 */
public final class Disassemble extends Handler {
	/**
	 * Constructor for the Disassemble handler
	 *
	 * @param tool the PluginTool instance
	 */
	public Disassemble(PluginTool tool) {
		super(tool, "/disassemble");
	}

	/**
	 * Handle the HTTP request to disassemble at one or more addresses.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String modeStr = params.get("mode");
		long length = parseLongOrDefault(params.get("length"), 0);

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		if (length < 0) {
			sendResponse(exchange, "Error: length cannot be negative");
			return;
		}
		Disassemblers.Mode mode = Disassemblers.parseMode(modeStr);
		if (mode == null) {
			sendResponse(exchange, "Error: unknown mode '" + modeStr
					+ "'. Known modes: " + Disassemblers.modeNames());
			return;
		}
		sendResponse(exchange, disassemble(address, mode, length));
	}

	/**
	 * Disassembles at each of the given addresses.
	 *
	 * @param addressList one address, or several separated by commas
	 * @param mode        which instruction set to decode as
	 * @param length      bytes to stay within, or 0 to follow flow unbounded
	 * @return a per-address report
	 */
	private String disassemble(String addressList, Disassemblers.Mode mode, long length) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		String unsupported = Disassemblers.unsupported(program, mode);
		if (unsupported != null)
			return "Error: " + unsupported;

		List<String> addresses = splitAddresses(addressList);
		if (addresses.isEmpty())
			return "Error: address is required";

		final AtomicReference<String> result = new AtomicReference<>();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction(tx("Disassemble"));
				boolean success = false;
				StringBuilder report = new StringBuilder();
				int done = 0, already = 0, failed = 0;

				try {
					for (String addrStr : addresses) {
						Address addr = parseAddress(program, addrStr);
						if (addr == null) {
							report.append(addrStr).append(": invalid address\n");
							failed++;
							continue;
						}

						Instruction existing = program.getListing().getInstructionAt(addr);
						if (existing != null) {
							// Already code. Say what is there rather than
							// re-disassembling it, which would either be a no-op
							// or -- with a different mode -- silently reinterpret
							// instructions something else may already refer to.
							Function in = program.getFunctionManager().getFunctionContaining(addr);
							report.append(addrStr).append(": already an instruction (")
									.append(existing.toString()).append(")")
									.append(in != null ? ", inside " + in.getName() : "")
									.append(". Use clear_code first to redo it\n");
							already++;
							continue;
						}

						AddressSetView restricted = null;
						if (length > 0) {
							Address end = endOf(addr, length);
							if (end == null) {
								report.append(addrStr)
										.append(": length runs past the end of the address space\n");
								failed++;
								continue;
							}
							restricted = new AddressSet(addr, end);
						}

						DisassembleCommand cmd = Disassemblers.command(addr, restricted, mode);
						boolean ok = cmd.applyTo(program);
						AddressSetView made = cmd.getDisassembledAddressSet();
						long bytes = (made == null) ? 0 : made.getNumAddresses();

						if (!ok || bytes == 0) {
							String why = cmd.getStatusMsg();
							report.append(addrStr).append(": disassembly failed")
									.append(why != null && !why.isEmpty() ? " -- " + why : "")
									.append("\n");
							failed++;
							continue;
						}

						report.append(addrStr).append(": disassembled ").append(bytes)
								.append(" bytes");
						if (made.getNumAddressRanges() > 1) {
							report.append(" in ").append(made.getNumAddressRanges())
									.append(" ranges, ").append(made.getMinAddress())
									.append(" - ").append(made.getMaxAddress());
						}
						report.append("\n");
						done++;
					}

					report.append("\n").append(done).append(" disassembled, ")
							.append(already).append(" already code, ")
							.append(failed).append(" failed");
					result.set(report.toString());
					success = done > 0;
				} catch (Exception e) {
					result.set("Error: Failed to disassemble: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute disassemble on Swing thread: " + e.getMessage();
		}
		return result.get();
	}

	/**
	 * The last address of a run of `length` bytes starting at `start`.
	 *
	 * @param start  first address
	 * @param length how many bytes
	 * @return the last address, or null if the run leaves the address space
	 */
	private static Address endOf(Address start, long length) {
		try {
			return start.addNoWrap(length - 1);
		} catch (Exception e) {
			return null;
		}
	}
}
