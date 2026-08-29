package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolTable;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for removing a label from an address.
 *
 * The counterpart create_label never had, and the reason delete_function was
 * not the inverse of create_function it claimed to be: removing a function
 * removes the function, not the symbol. A function created and then renamed
 * leaves its name behind as a USER_DEFINED label when it is deleted, so
 * repairing a misaimed create_function left a symbol pointing at bytes that
 * had gone back to being undefined -- and nothing here could take it off.
 *
 * Only labels are removed. A symbol that is the name of a live function is
 * refused, because deleting it would be a rename to a default name rather
 * than the removal the caller asked for; delete the function instead.
 */
public final class DeleteLabel extends Handler {
	/**
	 * Constructor for the DeleteLabel handler
	 *
	 * @param tool the PluginTool instance
	 */
	public DeleteLabel(PluginTool tool) {
		super(tool, "/delete_label");
	}

	/**
	 * Handle the HTTP request to remove a label.
	 *
	 * Accepts "address", and an optional "name" to remove one label of several
	 * at that address. Without a name, every user-defined label there goes.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String name = params.get("name");

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		sendResponse(exchange, deleteLabel(address, name));
	}

	/**
	 * Removes labels at an address.
	 *
	 * @param addressStr where to look
	 * @param name       which label, or null for all user-defined ones there
	 * @return what was removed
	 */
	private String deleteLabel(String addressStr, String name) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Address addr = parseAddress(program, addressStr);
		if (addr == null)
			return "Error: invalid address " + addressStr;

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction(tx("Delete Label"));
				boolean success = false;
				try {
					SymbolTable table = program.getSymbolTable();
					Symbol[] symbols = table.getSymbols(addr);
					List<String> removed = new ArrayList<>();
					List<String> kept = new ArrayList<>();

					for (Symbol symbol : symbols) {
						if (name != null && !name.isEmpty() && !symbol.getName().equals(name)) {
							continue;
						}
						// A dynamic symbol is not stored -- it is the display
						// name Ghidra makes up for an address, so there is
						// nothing to delete and nothing to report.
						if (symbol.isDynamic()) {
							continue;
						}
						if (symbol.getSymbolType() == SymbolType.FUNCTION) {
							kept.add(symbol.getName() + " (names a function; delete_function instead)");
							continue;
						}
						String symbolName = symbol.getName();
						if (symbol.delete()) {
							removed.add(symbolName);
						} else {
							kept.add(symbolName + " (Ghidra refused to remove it)");
						}
					}

					StringBuilder sb = new StringBuilder();
					if (removed.isEmpty() && kept.isEmpty()) {
						sb.append("No label to remove at ").append(addr)
								.append(name != null && !name.isEmpty()
										? " named '" + name + "'" : "");
					} else {
						if (!removed.isEmpty()) {
							sb.append("Removed ").append(String.join(", ", removed))
									.append(" from ").append(addr);
						}
						for (String k : kept) {
							sb.append(sb.length() > 0 ? "\n" : "").append("Kept ").append(k);
						}
					}
					result.set(sb.toString());
					success = !removed.isEmpty();
				} catch (Exception e) {
					result.set("Error: failed to delete label: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to delete label on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
