package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for writing the program back to the project.
 *
 * Everything the MCP does -- every rename, every created function, every
 * comment -- lived only in memory until somebody clicked Save in the GUI. A
 * session could work for an hour and lose all of it to a crash, and an agent
 * driving Ghidra unattended had no way to commit its own work at all.
 */
public final class SaveProgram extends Handler {
	/**
	 * Constructor for the SaveProgram handler
	 *
	 * @param tool the PluginTool instance
	 */
	public SaveProgram(PluginTool tool) {
		super(tool, "/save_program");
	}

	/**
	 * Handle the HTTP request to save the current program.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, save());
	}

	/**
	 * Saves the current program to its domain file.
	 *
	 * Deliberately NOT wrapped in invokeAndWait. Saving takes a lock on the
	 * program and can run for seconds on a large database; Ghidra's own Save
	 * runs it as a background task for exactly that reason, and putting it on
	 * the Swing thread would freeze the GUI for the duration while giving the
	 * caller nothing extra.
	 *
	 * @return what was saved, or why it was not
	 */
	private String save() {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		DomainFile file = program.getDomainFile();
		if (file == null)
			return "This program has no file in a project, so there is nowhere to save it";
		if (file.isReadOnly())
			return "Refused: " + file.getName() + " is read-only";
		if (!file.isChanged())
			return file.getName() + " has no unsaved changes";
		if (!file.canSave())
			return "Refused: " + file.getName() + " cannot be saved"
					+ (file.isCheckedOut() ? "" : " (it may need to be checked out first)");

		try {
			file.save(TaskMonitor.DUMMY);
			return "Saved " + file.getName() + " to " + file.getPathname();
		} catch (Exception e) {
			return "Error: failed to save " + file.getName() + ": " + e.getMessage();
		}
	}
}
