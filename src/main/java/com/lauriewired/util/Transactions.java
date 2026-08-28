package com.lauriewired.util;

/**
 * Names for Ghidra transactions.
 */
public final class Transactions {

	private Transactions() {
	}

	/** Longest session tag written into a transaction name. */
	private static final int MAX_TAG = 32;

	/** The name a transaction is recorded under, given the session that asked for it. */
	public static String name(String base, String sessionTag) {
		String tag = clean(sessionTag);
		if (tag.isEmpty()) {
			return base;
		}
		return base + " [" + tag + "]";
	}

	/**
	 * The tag arrives in a request header, so it is whatever a caller sent, and
	 * it ends up in a project's permanent history. Keep only what is safe to
	 * write there.
	 */
	private static String clean(String sessionTag) {
		if (sessionTag == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < sessionTag.length() && sb.length() < MAX_TAG; i++) {
			char c = sessionTag.charAt(i);
			if (Character.isLetterOrDigit(c) || c == '_' || c == '-') {
				sb.append(c);
			}
		}
		return sb.toString();
	}
}
