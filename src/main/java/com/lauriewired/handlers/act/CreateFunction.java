package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.lauriewired.util.Disassemblers;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static com.lauriewired.util.ParseUtils.splitAddresses;
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
		String modeStr = params.get("mode");

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		Disassemblers.Mode mode = Disassemblers.parseMode(modeStr);
		if (mode == null) {
			sendResponse(exchange, "Error: unknown mode '" + modeStr
					+ "'. Known modes: " + Disassemblers.modeNames());
			return;
		}
		sendResponse(exchange, createFunctions(address, name, mode));
	}

	/**
	 * Creates a function at each of the given addresses.
	 *
	 * @param addressList one address, or several separated by commas
	 * @param name        optional name, applied only for a single address
	 * @param mode        which instruction set to decode undefined bytes as
	 * @return a per-address report
	 */
	private String createFunctions(String addressList, String name, Disassemblers.Mode mode) {
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
				int txId = program.startTransaction(tx("Create Function"));
				boolean success = false;
				StringBuilder report = new StringBuilder();
				int created = 0, existing = 0, failed = 0;

				try {
					for (String addrStr : addresses) {
						Address addr = parseAddress(program, addrStr);
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

						// Inside another function, which is not the same as undefined.
						// Ghidra will happily define one here and SPLIT the body it
						// lands in, leaving both halves decompiling into fragments
						// full of unaff_ registers. That is not a hypothetical: four
						// calls aimed at one program's addresses were answered by a
						// second Ghidra holding a different game — same engine, same
						// link order, so the addresses existed in both — and split
						// three real functions before anyone noticed. Refusing here
						// makes a misaimed call say so instead of quietly damaging a
						// database, and the caller who really means it can delete the
						// containing function first.
						Function containing =
								program.getFunctionManager().getFunctionContaining(addr);
						if (containing != null) {
							report.append(addrStr)
									.append(": inside ").append(containing.getName())
									.append(" @ ").append(containing.getEntryPoint())
									.append(" — creating here would split it. Refused; "
											+ "delete that function first if you mean to\n");
							failed++;
							continue;
						}

						// Undefined bytes cannot become a function until they are code.
						Instruction instr = program.getListing().getInstructionAt(addr);
						if (instr == null) {
							// The restricted set is null on purpose: it is the set
							// of addresses disassembly is ALLOWED to touch, and this
							// call used to pass a one-byte set built from addr. The
							// disassembler decoded the instruction at addr, stepped
							// to the next address, found it outside the set and
							// stopped. CreateFunctionCmd then computed the body by
							// following flow over the instructions that existed --
							// exactly one -- so every function created from
							// undefined bytes was one instruction long and was
							// reported as created. Null means follow the flow.
							DisassembleCommand disassemble =
									Disassemblers.command(addr, null, mode);
							disassemble.applyTo(program);
							instr = program.getListing().getInstructionAt(addr);
							if (instr == null) {
								String why = disassemble.getStatusMsg();
								report.append(addrStr).append(": disassembly failed")
										.append(why != null && !why.isEmpty() ? " -- " + why : "")
										.append("\n");
								failed++;
								continue;
							}
						}

						String funcName = (addresses.size() == 1 && name != null && !name.isEmpty())
								? name : null;
						CreateFunctionCmd cmd =
								new CreateFunctionCmd(funcName, addr, null, SourceType.USER_DEFINED);

						if (cmd.applyTo(program)) {
							Function madeFunc = program.getFunctionManager().getFunctionAt(addr);
							report.append(addrStr).append(": created as ")
									.append(madeFunc != null ? madeFunc.getName() : "?")
									.append(describeBody(program, madeFunc))
									.append("\n");
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

	/**
	 * How big the function that was just created actually is.
	 *
	 * A one-instruction function is what a create over undefined bytes used to
	 * produce every single time, and the reply said only "created" -- the
	 * damage showed up later, as a decompilation that made no sense. Saying
	 * the size in the reply is what makes that visible at the moment it
	 * happens, and a body of one instruction is called out rather than left
	 * for the caller to notice in a number.
	 *
	 * @param program the program
	 * @param func    the function just created, or null
	 * @return a parenthesised summary, or the empty string if there is nothing
	 *         to say
	 */
	private static String describeBody(Program program, Function func) {
		if (func == null) {
			return "";
		}
		AddressSetView body = func.getBody();
		long bytes = body.getNumAddresses();
		int instructions = 0;
		InstructionIterator it = program.getListing().getInstructions(body, true);
		while (it.hasNext()) {
			it.next();
			instructions++;
		}
		StringBuilder sb = new StringBuilder();
		sb.append(" (").append(bytes).append(" bytes, ")
				.append(instructions).append(instructions == 1 ? " instruction" : " instructions");
		if (instructions == 1) {
			sb.append(" -- suspiciously small; the flow may be unreachable, "
					+ "or the bytes may need a different mode");
		}
		return sb.append(")").toString();
	}
}
