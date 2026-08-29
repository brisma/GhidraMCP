package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parseAddress;
import static com.lauriewired.util.ParseUtils.parseLongOrDefault;
import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for reading the listing over an arbitrary range, code or not.
 *
 * Every other reader here needs a function first: disassemble_function and
 * both decompilers refuse an address that is not inside one, which makes
 * undefined bytes unreachable -- you could not look at the thing you were
 * about to define, only guess and find out afterwards.
 *
 * This shows what the CodeBrowser shows: instructions where there are
 * instructions, defined data where there is data, and `??` rows for raw
 * bytes, with labels and comments where they exist.
 */
public final class ReadListing extends Handler {

	/** Rows returned when the caller does not say. */
	private static final int DEFAULT_COUNT = 64;

	/** Most rows returned however large the request. */
	private static final int MAX_COUNT = 2000;

	/**
	 * Constructor for the ReadListing handler
	 *
	 * @param tool the PluginTool instance
	 */
	public ReadListing(PluginTool tool) {
		super(tool, "/read_listing");
	}

	/**
	 * Handles HTTP requests to read the listing.
	 *
	 * Accepts "address" (required), and one of "count" (code units) or
	 * "length" (bytes). Defaults to {@value #DEFAULT_COUNT} code units.
	 *
	 * @param exchange the HTTP exchange containing the request
	 * @throws IOException if an I/O error occurs during handling
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		long count = parseLongOrDefault(qparams.get("count"), 0);
		long length = parseLongOrDefault(qparams.get("length"), 0);
		sendResponse(exchange, readListing(address, count, length));
	}

	/**
	 * Reads the listing starting at an address.
	 *
	 * @param addressStr where to start
	 * @param count      code units to return, or 0 to use the length
	 * @param length     bytes to cover, or 0 to use the count
	 * @return one line per code unit
	 */
	private String readListing(String addressStr, long count, long length) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		Address start = parseAddress(program, addressStr);
		if (start == null)
			return "Error: invalid address " + addressStr;
		if (!program.getMemory().contains(start))
			return "Error: " + start + " is not in mapped memory";

		if (count < 0 || length < 0)
			return "Error: count and length cannot be negative";

		Address end = null;
		if (length > 0) {
			try {
				end = start.addNoWrap(length - 1);
			} catch (Exception e) {
				end = null; // runs off the space; the memory bound below stops us
			}
		}
		long limit = (count > 0) ? Math.min(count, MAX_COUNT)
				: (length > 0 ? MAX_COUNT : DEFAULT_COUNT);

		Listing listing = program.getListing();
		// Bound by the START's own address space, not the program's highest
		// address: with an overlay loaded those are in different spaces, and
		// AddressSet refuses a range that spans two.
		if (end == null) {
			end = start.getAddressSpace().getMaxAddress();
		}
		AddressSet range = new AddressSet(start, end);

		StringBuilder out = new StringBuilder();
		long rows = 0;
		boolean truncated = false;

		// getCodeUnits over a set yields undefined bytes too, as Data whose
		// type is the default one -- which is exactly how the CodeBrowser
		// renders a region that has never been touched.
		CodeUnitIterator it = listing.getCodeUnits(range, true);
		while (it.hasNext()) {
			if (rows >= limit) {
				truncated = true;
				break;
			}
			CodeUnit cu = it.next();
			out.append(format(program, cu)).append("\n");
			rows++;
		}

		if (rows == 0)
			return "Nothing readable at " + start;
		if (truncated) {
			out.append("... stopped after ").append(rows)
					.append(count > 0 || length > 0 ? " code units" : " code units (default)")
					.append("; continue from the next address\n");
		}
		return out.toString();
	}

	/**
	 * One listing row: address, bytes, what it is, and anything written on it.
	 *
	 * @param program the program
	 * @param cu      the code unit
	 * @return the formatted line
	 */
	private static String format(Program program, CodeUnit cu) {
		Address addr = cu.getMinAddress();
		Listing listing = program.getListing();
		StringBuilder line = new StringBuilder();

		// Above the code unit, in the order the CodeBrowser stacks them.
		// Every type is shown and named: this used to render EOL only, so a
		// plate comment written through set_comment was invisible to the tool
		// that was supposed to read it back.
		append(line, listing.getComment(CommentType.PLATE, addr), "plate");
		append(line, listing.getComment(CommentType.PRE, addr), "pre");

		Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);
		Function funcAt = program.getFunctionManager().getFunctionAt(addr);
		if (funcAt != null) {
			line.append("       ").append(funcAt.getName()).append(":\n");
		} else if (primary != null && primary.isPrimary()) {
			line.append("       ").append(primary.getName()).append(":\n");
		}

		line.append(addr).append("  ");
		line.append(String.format("%-24s", bytesOf(cu)));

		if (cu instanceof Instruction instr) {
			line.append(instr.toString());
		} else if (cu instanceof Data data) {
			if (data.isDefined()) {
				line.append(data.getDataType().getName()).append(" ")
						.append(String.valueOf(data.getDefaultValueRepresentation()));
			} else {
				line.append("??");
			}
		} else {
			line.append(cu.toString());
		}

		String eol = listing.getComment(CommentType.EOL, addr);
		if (eol != null && !eol.isEmpty()) {
			line.append("   ; ").append(eol.replace('\n', ' '));
		}

		// Below it.
		StringBuilder below = new StringBuilder();
		append(below, listing.getComment(CommentType.POST, addr), "post");
		append(below, listing.getComment(CommentType.REPEATABLE, addr), "repeatable");
		if (below.length() > 0) {
			line.append("\n").append(below, 0, below.length() - 1);
		}
		return line.toString();
	}

	/**
	 * Adds a comment to the output, one prefixed line per line of comment.
	 *
	 * @param out   where to write
	 * @param text  the comment, or null if there is none of this type here
	 * @param label which type it is, so a reader can tell them apart
	 */
	private static void append(StringBuilder out, String text, String label) {
		if (text == null || text.isEmpty()) {
			return;
		}
		for (String part : text.split("\n")) {
			out.append("            [").append(label).append("] ").append(part).append("\n");
		}
	}

	/**
	 * The raw bytes of a code unit, as hex.
	 *
	 * @param cu the code unit
	 * @return space-separated hex, or "??" if the bytes cannot be read
	 */
	private static String bytesOf(CodeUnit cu) {
		try {
			byte[] bytes = cu.getBytes();
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length && i < 8; i++) {
				sb.append(String.format("%02X ", bytes[i]));
			}
			if (bytes.length > 8) {
				sb.append("...");
			}
			return sb.toString().trim();
		} catch (Exception e) {
			return "??";
		}
	}
}
