package com.lauriewired.util;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * The instance is the only party that knows, at the moment it acts, which
 * database it is. These are the rules by which it decides to act or refuse.
 */
public class IdentityGuardTest {

	@Test
	public void refusesARequestThatNamesAnotherDatabase() {
		assertTrue(IdentityGuard.refuses("aaaa-1111", "bbbb-2222"));
	}

	@Test
	public void allowsARequestThatNamesThisDatabase() {
		assertFalse(IdentityGuard.refuses("aaaa-1111", "aaaa-1111"));
	}

	/**
	 * A request that declares nothing is a human at a shell, checking by hand
	 * on an explicit port. That is the escape hatch used when the bridge is not
	 * trusted, so it must keep working; the bridge itself always declares.
	 */
	@Test
	public void allowsARequestThatDeclaresNothing() {
		assertFalse(IdentityGuard.refuses(null, "aaaa-1111"));
	}
}
