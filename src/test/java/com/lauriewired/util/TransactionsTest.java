package com.lauriewired.util;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Ghidra records a name per transaction, in the undo stack and the project
 * history. Generic names throw away the one fact nobody could recover after
 * four functions appeared in a database: who made them.
 */
public class TransactionsTest {

	@Test
	public void namesTheSessionThatAsked() {
		assertEquals("Create Function [cc7b64c9]",
				Transactions.name("Create Function", "cc7b64c9"));
	}

	@Test
	public void leavesTheNameAloneWhenNobodySaidWhoWasAsking() {
		assertEquals("Create Function", Transactions.name("Create Function", null));
		assertEquals("Create Function", Transactions.name("Create Function", ""));
	}

	/**
	 * The tag arrives in a request header, so it is whatever a caller sent. It
	 * ends up in a database's permanent history, and must not be able to carry
	 * brackets, newlines or length into it.
	 */
	@Test
	public void keepsOnlyWhatIsSafeToWriteIntoAProjectHistory() {
		assertEquals("Rename data [abc123]",
				Transactions.name("Rename data", "abc]\n 123"));
		assertEquals("Rename data [" + "a".repeat(32) + "]",
				Transactions.name("Rename data", "a".repeat(80)));
	}
}
