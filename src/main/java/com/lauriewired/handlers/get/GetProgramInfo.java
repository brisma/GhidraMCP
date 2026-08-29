package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler describing what this program actually is.
 *
 * Nothing here reported the processor, the endianness or the pointer size, so
 * a caller had to infer them from the shape of the addresses it got back --
 * and a caller that guesses wrong asks for THUMB on a MIPS binary, or reads a
 * pointer as four bytes on an AArch64 one. It is also the cheapest way to
 * confirm which database answered, without parsing a listing.
 */
public final class GetProgramInfo extends Handler {
	/**
	 * Constructor for the GetProgramInfo handler
	 *
	 * @param tool the PluginTool instance
	 */
	public GetProgramInfo(PluginTool tool) {
		super(tool, "/program_info");
	}

	/**
	 * Handle the HTTP request for program metadata.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, describe());
	}

	/**
	 * @return one "key: value" line per fact about the loaded program
	 */
	private String describe() {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Language language = program.getLanguage();
		Memory memory = program.getMemory();
		DomainFile file = program.getDomainFile();

		StringBuilder sb = new StringBuilder();
		sb.append("name: ").append(program.getName()).append("\n");
		if (file != null) {
			sb.append("file: ").append(file.getPathname()).append("\n");
			sb.append("file_id: ").append(String.valueOf(file.getFileID())).append("\n");
			sb.append("unsaved_changes: ").append(file.isChanged()).append("\n");
		}
		sb.append("executable_path: ").append(String.valueOf(program.getExecutablePath())).append("\n");
		sb.append("executable_format: ").append(String.valueOf(program.getExecutableFormat())).append("\n");
		sb.append("executable_md5: ").append(String.valueOf(program.getExecutableMD5())).append("\n");
		sb.append("executable_sha256: ").append(String.valueOf(program.getExecutableSHA256())).append("\n");
		sb.append("language_id: ").append(language.getLanguageID()).append("\n");
		sb.append("processor: ").append(language.getProcessor()).append("\n");
		sb.append("endian: ").append(language.isBigEndian() ? "big" : "little").append("\n");
		sb.append("address_size_bits: ").append(language.getLanguageDescription().getSize())
				.append("\n");
		sb.append("pointer_size_bytes: ").append(program.getDefaultPointerSize()).append("\n");
		sb.append("compiler_spec: ").append(program.getCompilerSpec().getCompilerSpecID())
				.append("\n");
		sb.append("image_base: ").append(program.getImageBase()).append("\n");
		sb.append("min_address: ").append(String.valueOf(memory.getMinAddress())).append("\n");
		sb.append("max_address: ").append(String.valueOf(memory.getMaxAddress())).append("\n");
		sb.append("function_count: ").append(program.getFunctionManager().getFunctionCount())
				.append("\n");
		sb.append("symbol_count: ").append(program.getSymbolTable().getNumSymbols()).append("\n");

		// Which context registers exist decides which disassembly modes are
		// usable here, and asking for one the language has no register for is
		// the mistake this endpoint exists to prevent.
		sb.append("thumb_capable: ")
				.append(program.getProgramContext().getRegister("TMode") != null).append("\n");
		sb.append("mips16_capable: ")
				.append(program.getProgramContext().getRegister("ISA_MODE") != null).append("\n");
		return sb.toString();
	}
}
