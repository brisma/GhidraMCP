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
 * Handler for taking back the last change to the program.
 *
 * The undo stack is shared with everything else touching this program -- other
 * sessions, and the person in the GUI. The names carry the session tag each
 * transaction was opened with, so a caller can see whose work is on top before
 * stepping it; dry_run=true reports without changing anything.
 */
public final class Undo extends Handler {
	/**
	 * Constructor for the Undo handler
	 *
	 * @param tool the PluginTool instance
	 */
	public Undo(PluginTool tool) {
		super(tool, "/undo");
	}

	/**
	 * Handle the HTTP request to undo.
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
		sendResponse(exchange, UndoStack.step(program, true, count, dryRun));
	}
}
