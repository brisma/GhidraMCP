package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parseLongOrDefault;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for running Ghidra's auto-analysis.
 *
 * Newly disassembled code is queued for analysis but nothing here ever asked
 * for that queue to be run, so functions found by following flow, references
 * discovered from new instructions and stack frames were all left waiting for
 * whatever the GUI happened to do next.
 *
 * With no address, this drains the pending queue -- what the GUI does by
 * itself after you press D. With an address (and optionally a length) it
 * re-analyses that range from scratch, which is the more expensive thing and
 * so is never the default.
 */
public final class AnalyzeProgram extends Handler {
	/**
	 * Constructor for the AnalyzeProgram handler
	 *
	 * @param tool the PluginTool instance
	 */
	public AnalyzeProgram(PluginTool tool) {
		super(tool, "/analyze");
	}

	/**
	 * Handle the HTTP request to analyze.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		long length = parseLongOrDefault(params.get("length"), 0);

		if (length < 0) {
			sendResponse(exchange, "Error: length cannot be negative");
			return;
		}
		sendResponse(exchange, analyze(address, length));
	}

	/**
	 * Schedules analysis and returns without waiting for it.
	 *
	 * Analysis of a large program runs for minutes. Blocking the handler for
	 * that long would hold the instance's single request thread the whole
	 * time -- every other call from every other session would queue behind
	 * it -- so this reports what was scheduled and lets it run.
	 *
	 * @param addressStr where to re-analyse from, or null for the pending queue
	 * @param length     bytes to cover, or 0 for a single address
	 * @return what was scheduled
	 */
	private String analyze(String addressStr, long length) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AddressSet range;
		if (addressStr != null && !addressStr.isEmpty()) {
			Address start = parseAddress(program, addressStr);
			if (start == null)
				return "Error: invalid address " + addressStr;
			Address end = start;
			if (length > 0) {
				try {
					end = start.addNoWrap(length - 1);
				} catch (Exception e) {
					return "Error: length runs past the end of the address space";
				}
			}
			range = new AddressSet(start, end);
		} else {
			range = null;
		}

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
				if (mgr == null) {
					result.set("This program has no analysis manager");
					return;
				}
				if (range != null) {
					int txId = program.startTransaction(tx("Analyze"));
					boolean success = false;
					try {
						mgr.reAnalyzeAll(range);
						success = true;
					} catch (Exception e) {
						result.set("Error: failed to queue analysis: " + e.getMessage());
						return;
					} finally {
						program.endTransaction(txId, success);
					}
				}
				boolean started = mgr.startBackgroundAnalysis();
				if (!started) {
					result.set(range != null
							? "Queued re-analysis of " + range.getMinAddress() + " - "
									+ range.getMaxAddress()
									+ ", but background analysis could not be started "
									+ "(analysis may be disabled for this tool)"
							: "Nothing to analyze, or background analysis is disabled "
									+ "for this tool");
					return;
				}
				result.set(range != null
						? "Re-analysing " + range.getMinAddress() + " - " + range.getMaxAddress()
								+ " in the background"
						: "Running pending analysis in the background");
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to start analysis on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
