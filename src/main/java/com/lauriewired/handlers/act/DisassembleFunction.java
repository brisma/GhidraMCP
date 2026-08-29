package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for disassembling a function at a given address in Ghidra
 * 
 * This handler responds to HTTP requests to disassemble a function
 * and returns the assembly code as a string.
 */
public final class DisassembleFunction extends Handler {
	/**
	 * Constructor for the DisassembleFunction handler
	 * 
	 * @param tool the Ghidra plugin tool instance
	 */
	public DisassembleFunction(PluginTool tool) {
		super(tool, "/disassemble_function");
	}

	/**
	 * Handles HTTP requests to disassemble a function at a specified address
	 * 
	 * @param exchange the HTTP exchange containing the request
	 * @throws IOException if an I/O error occurs during handling
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		sendResponse(exchange, disassembleFunction(address));
	}

	/**
	 * Disassembles the function at the specified address and returns the assembly
	 * code
	 * 
	 * @param addressStr the address of the function to disassemble
	 * @return a string containing the disassembled function code
	 */
	private String disassembleFunction(String addressStr) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getListing().getFunctionContaining(addr);
			if (func == null)
				return "No function found at or containing address " + addressStr;

			StringBuilder result = new StringBuilder();
			Listing listing = program.getListing();

			// Iterate the BODY, not entry..maxAddress. A function body is a set
			// of ranges, not one span: compilers put cold blocks elsewhere and
			// split hot paths, so walking straight from the entry to the body's
			// highest address also walks through whatever sits in the gaps --
			// other functions' instructions, reported as part of this one.
			InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
			while (instructions.hasNext()) {
				Instruction instr = instructions.next();
				String comment = listing.getComment(CommentType.EOL, instr.getAddress());
				comment = (comment != null) ? "; " + comment : "";

				result.append(String.format("%s: %s %s\n",
						instr.getAddress(),
						instr.toString(),
						comment));
			}

			if (result.length() == 0)
				return "No instructions in the body of " + func.getName()
						+ " @ " + func.getEntryPoint();

			return result.toString();
		} catch (Exception e) {
			return "Error disassembling function: " + e.getMessage();
		}
	}
}
