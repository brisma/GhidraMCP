package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.lauriewired.util.UndoStack;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parseIntOrDefault;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for re-applying a change that was undone.
 *
 * The redo stack is emptied by the next write from anyone, so a redo that was
 * available a moment ago may not be now. Like {@link Undo}, the stack is
 * shared with other sessions and with the GUI; dry_run=true reports what is
 * there without touching it.
 */
public final class Redo extends Handler {
	/**
	 * Constructor for the Redo handler
	 *
	 * @param tool the PluginTool instance
	 */
	public Redo(PluginTool tool) {
		super(tool, "/redo");
	}

	/**
	 * Handle the HTTP request to redo.
	 *
	 * Accepts an optional "count" (default 1) and "dry_run".
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		int count = parseIntOrDefault(params.get("count"), 1);
		boolean dryRun = Boolean.parseBoolean(params.get("dry_run"));

		if (count < 1) {
			sendResponse(exchange, "Error: count must be at least 1");
			return;
		}
		Program program = getCurrentProgram(tool);
		if (program == null) {
			sendResponse(exchange, "No program loaded");
			return;
		}
		sendResponse(exchange, UndoStack.step(program, false, count, dryRun));
	}
}
