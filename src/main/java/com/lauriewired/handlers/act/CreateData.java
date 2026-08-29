package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.GhidraUtils.resolveDataType;
import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for applying a data type at an address -- Ghidra's T key.
 *
 * set_global_data_type could retype an address that already held data, but
 * nothing could lay data down on undefined bytes in the first place. Between
 * that and the missing disassembler, raw bytes could be neither code nor data:
 * whatever auto-analysis had decided was all you were ever going to get.
 */
public final class CreateData extends Handler {
	/**
	 * Constructor for the CreateData handler
	 *
	 * @param tool the PluginTool instance
	 */
	public CreateData(PluginTool tool) {
		super(tool, "/create_data");
	}

	/**
	 * Handle the HTTP request to create data.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String type = params.get("type");
		boolean force = Boolean.parseBoolean(params.get("force"));

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}
		if (type == null || type.isEmpty()) {
			sendResponse(exchange, "Error: type is required");
			return;
		}
		sendResponse(exchange, createData(address, type, force));
	}

	/**
	 * Applies a data type at an address.
	 *
	 * @param addressStr where to apply it
	 * @param typeName   the data type, e.g. "int", "char[16]", "MyStruct *"
	 * @param force      clear whatever is already defined there
	 * @return what happened
	 */
	private String createData(String addressStr, String typeName, boolean force) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Address addr = parseAddress(program, addressStr);
		if (addr == null)
			return "Error: invalid address " + addressStr;
		if (!program.getMemory().contains(addr))
			return "Error: " + addr + " is not in mapped memory";

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = resolveDataType(tool, dtm, typeName);
		if (dataType == null)
			return "Error: unknown data type '" + typeName + "'";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction(tx("Create Data"));
				boolean success = false;
				try {
					CreateDataCmd cmd = new CreateDataCmd(addr, force, dataType);
					if (!cmd.applyTo(program)) {
						String why = cmd.getStatusMsg();
						result.set("Error: " + (why != null && !why.isEmpty() ? why
								: "could not apply " + dataType.getName() + " at " + addr
										+ (force ? "" : "; pass force=true to clear what is there")));
						return;
					}
					Data data = program.getListing().getDataAt(addr);
					result.set("Applied " + dataType.getName() + " at " + addr
							+ (data != null ? " (" + data.getLength() + " bytes)" : ""));
					success = true;
				} catch (Exception e) {
					result.set("Error: failed to create data: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to create data on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
