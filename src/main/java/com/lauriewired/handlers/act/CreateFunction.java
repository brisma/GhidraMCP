package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create one or more functions at given addresses.
 *
 * Auto-analysis often leaves code unreachable by static references — jump
 * table targets, hand-written assembly, raw memory dumps — as undefined
 * bytes. Those regions cannot be decompiled or disassembled through the
 * other endpoints, which all require an existing function. This handler
 * disassembles when needed and defines the function, so a whole jump table
 * can be opened up in one call.
 */
public final class CreateFunction extends Handler {
	/**
	 * Constructor for the CreateFunction handler
	 *
	 * @param tool the PluginTool instance
	 */
	public CreateFunction(PluginTool tool) {
		super(tool, "/create_function");
	}

	/**
	 * Handle the HTTP request to create functions.
	 *
	 * Accepts an "address" parameter holding one address or a comma-separated
	 * list, and an optional "name" used only when a single address is given.
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
		sendResponse(exchange, createFunctions(address, name));
	}

	/**
	 * Creates a function at each of the given addresses.
	 *
	 * @param addressList one address, or several separated by commas
	 * @param name        optional name, applied only for a single address
	 * @return a per-address report
	 */
	private String createFunctions(String addressList, String name) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		String[] addresses = addressList.split(",");
		final AtomicReference<String> result = new AtomicReference<>();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Function");
				boolean success = false;
				StringBuilder report = new StringBuilder();
				int created = 0, existing = 0, failed = 0;

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

						Function existingFunc = program.getFunctionManager().getFunctionAt(addr);
						if (existingFunc != null) {
							report.append(addrStr).append(": already defined as ")
									.append(existingFunc.getName()).append("\n");
							existing++;
							continue;
						}

						// Undefined bytes cannot become a function until they are code.
						Instruction instr = program.getListing().getInstructionAt(addr);
						if (instr == null) {
							DisassembleCommand disassemble =
									new DisassembleCommand(addr, new AddressSet(addr), true);
							disassemble.applyTo(program);
							instr = program.getListing().getInstructionAt(addr);
							if (instr == null) {
								report.append(addrStr).append(": disassembly failed\n");
								failed++;
								continue;
							}
						}

						String funcName = (addresses.length == 1 && name != null && !name.isEmpty())
								? name : null;
						CreateFunctionCmd cmd =
								new CreateFunctionCmd(funcName, addr, null, SourceType.USER_DEFINED);

						if (cmd.applyTo(program)) {
							Function created2 = program.getFunctionManager().getFunctionAt(addr);
							report.append(addrStr).append(": created as ")
									.append(created2 != null ? created2.getName() : "?").append("\n");
							created++;
						} else {
							report.append(addrStr).append(": ").append(cmd.getStatusMsg()).append("\n");
							failed++;
						}
					}

					report.append("\n").append(created).append(" created, ")
							.append(existing).append(" already defined, ")
							.append(failed).append(" failed");
					result.set(report.toString());
					success = created > 0;
				} catch (Exception e) {
					result.set("Error: Failed to create function: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create function on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
