package com.lauriewired.util;

import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for parsing HTTP requests and responses.
 * 
 * This class provides methods to parse query parameters, post body parameters,
 * paginate lists, parse integers with defaults, escape non-ASCII characters,
 * and send HTTP responses.
 */
public final class ParseUtils {
	/**
	 * Parse query parameters from the request URI.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of query parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a query string "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parseQueryParams(HttpExchange exchange) {
		// getRawQuery, not getQuery. URI.getQuery() hands back the query with
		// its percent-escapes ALREADY resolved, so splitting it on & and = cuts
		// on separators the caller had carefully escaped, and decoding the
		// pieces afterwards decodes them a second time. Both were observable:
		//
		//   GET /get_bytes?address=0x710163208c%26size=4
		//
		// was read as two parameters, and a filter of %2520 arrived as a space.
		// A value could therefore inject a parameter the caller never sent.
		return parseUrlEncoded(exchange.getRequestURI().getRawQuery());
	}

	/**
	 * Parse POST parameters from the request body.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of POST parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a body "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		return parseUrlEncoded(new String(body, StandardCharsets.UTF_8));
	}

	/**
	 * Split an application/x-www-form-urlencoded string into parameters.
	 *
	 * Splits on the raw separators FIRST and decodes each half exactly once,
	 * which is the only order that lets a value contain an escaped '&' or '='.
	 * A pair with no '=' at all yields an empty value rather than being
	 * dropped, so `name=` reaches the handler as "" -- handlers test for
	 * emptiness, and silently losing the key hid which of the two it was.
	 *
	 * @param raw the encoded string, or null
	 * @return the decoded parameters
	 */
	public static Map<String, String> parseUrlEncoded(String raw) {
		Map<String, String> result = new HashMap<>();
		if (raw == null || raw.isEmpty()) {
			return result;
		}
		for (String pair : raw.split("&")) {
			if (pair.isEmpty()) {
				continue;
			}
			int eq = pair.indexOf('=');
			String rawKey = (eq < 0) ? pair : pair.substring(0, eq);
			String rawValue = (eq < 0) ? "" : pair.substring(eq + 1);
			try {
				String key = URLDecoder.decode(rawKey, StandardCharsets.UTF_8);
				if (!key.isEmpty()) {
					result.put(key, URLDecoder.decode(rawValue, StandardCharsets.UTF_8));
				}
			} catch (Exception e) {
				Msg.error(ParseUtils.class, "Error decoding URL parameter", e);
			}
		}
		return result;
	}

	/**
	 * Paginate a list of items based on offset and limit.
	 * 
	 * @param items  The list of items to paginate.
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string containing the paginated items, each on a new line.
	 *         If the offset is beyond the list size, returns an empty string.
	 */
	public static String paginateList(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), offset + limit);

		if (start >= items.size()) {
			return ""; // no items in range
		}
		List<String> sub = items.subList(start, end);
		return String.join("\n", sub);
	}

	/**
	 * Parse an integer from a string, returning a default value if parsing fails.
	 * 
	 * @param val          The string to parse.
	 * @param defaultValue The default value to return if parsing fails.
	 * @return The parsed integer or the default value if parsing fails.
	 */
	public static int parseIntOrDefault(String val, int defaultValue) {
		if (val == null)
			return defaultValue;
		try {
			return Integer.parseInt(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Parse a long from a string, returning a default value if parsing fails.
	 *
	 * @param val          The string to parse.
	 * @param defaultValue The default value to return if parsing fails.
	 * @return The parsed long or the default value if parsing fails.
	 */
	public static long parseLongOrDefault(String val, long defaultValue) {
		if (val == null)
			return defaultValue;
		try {
			return Long.parseLong(val.trim());
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Resolve an address in a program, or null if the text does not name one.
	 *
	 * Ghidra's address factory throws for some malformed input and returns
	 * null for the rest; callers only ever want to know which addresses they
	 * can act on, so both become null here.
	 *
	 * @param program    the program whose address space to resolve against
	 * @param addressStr the address text
	 * @return the address, or null
	 */
	public static Address parseAddress(Program program, String addressStr) {
		if (program == null || addressStr == null || addressStr.trim().isEmpty()) {
			return null;
		}
		try {
			return program.getAddressFactory().getAddress(addressStr.trim());
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Split a comma-separated address parameter into its parts.
	 *
	 * Blank entries are dropped, so a trailing comma is not an error.
	 *
	 * @param addressList one address, or several separated by commas
	 * @return the non-empty pieces, in the order given
	 */
	public static List<String> splitAddresses(String addressList) {
		List<String> out = new ArrayList<>();
		if (addressList == null) {
			return out;
		}
		for (String raw : addressList.split(",")) {
			String trimmed = raw.trim();
			if (!trimmed.isEmpty()) {
				out.add(trimmed);
			}
		}
		return out;
	}

	/**
	 * Escape non-ASCII characters in a string.
	 *
	 * @param input The input string to escape.
	 * @return A string where non-ASCII characters are replaced with their
	 *         hexadecimal representation, e.g. "\xFF" for 255.
	 */
	public static String escapeNonAscii(String input) {
		if (input == null)
			return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Escape special characters in a string for safe display
	 * 
	 * @param input the string to escape
	 * @return the escaped string
	 */
	public static String escapeString(String input) {
		if (input == null)
			return "";

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else if (c == '\n') {
				sb.append("\\n");
			} else if (c == '\r') {
				sb.append("\\r");
			} else if (c == '\t') {
				sb.append("\\t");
			} else {
				sb.append(String.format("\\x%02x", (int) c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Send a plain text response to the HTTP exchange.
	 * 
	 * @param exchange The HttpExchange object to send the response to.
	 * @param response The response string to send.
	 * @throws IOException If an I/O error occurs while sending the response.
	 */
	public static void sendResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	/**
	 * Generate a hexdump of a byte array starting from a given base address.
	 * 
	 * @param base The base address to start the hexdump from.
	 * @param buf  The byte array to generate the hexdump for.
	 * @param len  The number of bytes to include in the hexdump.
	 * @return A string representation of the hexdump.
	 */
	public static String hexdump(Address base, byte[] buf, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i += 16) {
			sb.append(String.format("%s  ", base.add(i)));
			for (int j = 0; j < 16 && (i + j) < len; j++) {
				sb.append(String.format("%02X ", buf[i + j]));
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	/**
	 * Decode a hexadecimal string into a byte array.
	 * 
	 * @param hex The hexadecimal string to decode.
	 * @return A byte array representing the decoded hexadecimal string.
	 * @throws IllegalArgumentException If the input string is not a valid hex
	 *                                  string.
	 */
	public static byte[] decodeHex(String hex) {
		hex = hex.replaceAll("\\s+", "");
		if (hex.length() % 2 != 0)
			throw new IllegalArgumentException();
		byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}
}
