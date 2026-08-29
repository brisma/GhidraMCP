package com.lauriewired.handlers.comment;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CommentType;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.setCommentAtAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;

/**
 * Handler for any of Ghidra's five comment types at an address.
 *
 * There were two comment endpoints, hardcoded to EOL and PRE, which left
 * PLATE, POST and REPEATABLE unreachable. PLATE is the one that matters most
 * in practice -- it is the boxed header above a function, the natural place to
 * write down what a function is once you have worked it out.
 */
public final class SetComment extends Handler {
	/**
	 * Constructor for the SetComment handler
	 *
	 * @param tool the PluginTool instance
	 */
	public SetComment(PluginTool tool) {
		super(tool, "/set_comment");
	}

	/**
	 * Handle the HTTP request to set a comment.
	 *
	 * An empty comment clears the comment of that type, which is how Ghidra
	 * itself models deletion.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String comment = params.get("comment");
		String typeStr = params.get("type");

		if (address == null || address.isEmpty()) {
			sendResponse(exchange, "Error: address is required");
			return;
		}

		CommentType type = parseType(typeStr);
		if (type == null) {
			sendResponse(exchange, "Error: unknown comment type '" + typeStr
					+ "'. Known types: eol, pre, post, plate, repeatable");
			return;
		}

		String what = "Set " + type.name().toLowerCase() + " comment";
		boolean ok = setCommentAtAddress(tool, address, comment, type, tx(what));
		if (!ok) {
			sendResponse(exchange, "Failed to set comment at " + address);
			return;
		}
		sendResponse(exchange, (comment == null || comment.trim().isEmpty())
				? "Cleared the " + type.name().toLowerCase() + " comment at " + address
				: "Set the " + type.name().toLowerCase() + " comment at " + address);
	}

	/**
	 * Reads a comment type name, defaulting to EOL.
	 *
	 * @param raw the caller's type, or null
	 * @return the type, or null if the name is not one of Ghidra's
	 */
	private static CommentType parseType(String raw) {
		if (raw == null || raw.trim().isEmpty()) {
			return CommentType.EOL;
		}
		try {
			return CommentType.valueOf(raw.trim().toUpperCase());
		} catch (IllegalArgumentException e) {
			return null;
		}
	}
}
