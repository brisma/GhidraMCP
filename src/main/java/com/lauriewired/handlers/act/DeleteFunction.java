package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to delete one or more functions at given addresses.
 *
 * The inverse of {@link CreateFunction}, and it exists because its absence
 * has a cost: a create_function aimed at the wrong Ghidra instance splits a
 * real function into fragments, and with no delete endpoint the repair needs
 * a human in the GUI. That happened — four functions created from one game's
 * addresses landed in another game's database, because two instances were up
 * and the bridge could only see one of them.
 *
 * Deleting removes the function definition — its entry point, body, name,
 * parameters and local variables. The instructions themselves are untouched,
 * so the bytes stay disassembled and the region can be re-defined afterwards.
 */
public final class DeleteFunction extends Handler {
	/**
	 * Constructor for the DeleteFunction handler
	 *
	 * @param tool the PluginTool instance
	 */
	public DeleteFunction(PluginTool tool) {
		super(tool, "/delete_function");
	}

	/**
	 * Handle the HTTP request to delete functions.
	 *
	 * Accepts an "address" parameter holding one address or a comma-separated
	 * list.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		sendResponse(exchange, deleteFunctions(address));
	}

	/**
	 * Deletes the function at each of the given addresses.
	 *
	 * An address that holds no function is reported rather than treated as an
	 * error: deleting what is already absent is the outcome the caller wanted.
	 *
	 * @param addressList one address, or several separated by commas
	 * @return a per-address report
	 */
	private String deleteFunctions(String addressList) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		String[] addresses = addressList.split(",");
		final AtomicReference<String> result = new AtomicReference<>();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction(tx("Delete Function"));
				boolean success = false;
				StringBuilder report = new StringBuilder();
				int deleted = 0, absent = 0, failed = 0;

				try {
					for (String raw : addresses) {
						String addrStr = raw.trim();
						if (addrStr.isEmpty())
							continue;

						Address addr;
						try {
							addr = program.getAddressFactory().getAddress(addrStr);
						} catch (Exception e) {
							addr = null;
						}
						if (addr == null) {
							report.append(addrStr).append(": invalid address\n");
							failed++;
							continue;
						}

						// Only an entry point, never a containing function: deleting
						// the function an address merely sits inside would remove
						// something the caller did not name.
						Function func = program.getFunctionManager().getFunctionAt(addr);
						if (func == null) {
							Function containing =
									program.getFunctionManager().getFunctionContaining(addr);
							report.append(addrStr).append(": no function starts here")
									.append(containing != null
											? " (it is inside " + containing.getName()
													+ " @ " + containing.getEntryPoint()
													+ ", which is left alone)"
											: "")
									.append("\n");
							absent++;
							continue;
						}

						String name = func.getName();
						if (program.getFunctionManager().removeFunction(addr)) {
							report.append(addrStr).append(": deleted ").append(name).append("\n");
							deleted++;
						} else {
							report.append(addrStr).append(": Ghidra refused to remove ")
									.append(name).append("\n");
							failed++;
						}
					}

					report.append("\n").append(deleted).append(" deleted, ")
							.append(absent).append(" not present, ")
							.append(failed).append(" failed");
					result.set(report.toString());
					success = deleted > 0;
				} catch (Exception e) {
					result.set("Error: Failed to delete function: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute delete function on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
