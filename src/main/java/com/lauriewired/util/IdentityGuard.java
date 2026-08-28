package com.lauriewired.util;

/**
 * Decides whether a request may act on this instance's database.
 */
public final class IdentityGuard {

	private IdentityGuard() {
	}

	/**
	 * Must a request be refused?
	 *
	 * @param declared the database the caller says it is addressing, or null if
	 *                 it says nothing
	 * @param mine     the database this instance actually holds, or null if it
	 *                 holds none
	 */
	public static boolean refuses(String declared, String mine) {
		if (declared == null || declared.isEmpty()) {
			return false;
		}
		return !declared.equals(mine);
	}
}
