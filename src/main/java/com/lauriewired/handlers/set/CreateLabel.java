package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for putting a label on an address -- Ghidra's L key.
 *
 * rename_function and rename_data could only rename something that already
 * existed, so there was no way to name a jump-table entry, a data address that
 * had never been defined, or a place worth remembering in the middle of a
 * function. Naming things is most of reverse engineering; this is the part of
 * it that was missing.
 */
public final class CreateLabel extends Handler {
	/**
	 * Constructor for the CreateLabel handler
	 *
	 * @param tool the PluginTool instance
	 */
	public CreateLabel(PluginTool tool) {
		super(tool, "/create_label");
	}

	/**
	 * Handle the HTTP request to create a label.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String name = params.get("name");
		boolean primary = !"false".equalsIgnoreCase(params.get("primary"));

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		if (name == null || name.isEmpty()) {
			sendResponse(exchange, "Error: name is required");
			return;
		}
		sendResponse(exchange, createLabel(address, name, primary));
	}

	/**
	 * Creates a label at an address.
	 *
	 * @param addressStr where to put it
	 * @param name       the label
	 * @param primary    make it the address's primary symbol
	 * @return what happened
	 */
	private String createLabel(String addressStr, String name, boolean primary) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Address addr = parseAddress(program, addressStr);
		if (addr == null)
			return "Error: invalid address " + addressStr;
		if (!program.getMemory().contains(addr))
			return "Error: " + addr + " is not in mapped memory";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction(tx("Create Label"));
				boolean success = false;
				try {
					AddLabelCmd cmd = new AddLabelCmd(addr, name, SourceType.USER_DEFINED);
					if (!cmd.applyTo(program)) {
						result.set("Error: " + cmd.getStatusMsg());
						return;
					}
					if (primary) {
						Symbol symbol = program.getSymbolTable().getSymbol(name, addr, null);
						if (symbol != null && !symbol.isPrimary()) {
							symbol.setPrimary();
						}
					}
					result.set("Labelled " + addr + " as " + name);
					success = true;
				} catch (Exception e) {
					result.set("Error: failed to create label: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to create label on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
