package com.lauriewired.util;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Map;

/**
 * What a parameter value may contain without changing what the request means.
 *
 * The old parser read the query through URI.getQuery(), which resolves
 * percent-escapes, and only then split on '&' and '=' and decoded the halves
 * again. So an escaped separator inside a value became a real separator, and
 * a caller could add a parameter it never meant to send:
 *
 *   /get_bytes?address=0x710163208c%26size=4
 *
 * arrived as two parameters against a live instance. These tests pin the
 * order: split on the raw text, decode once.
 */
public class ParseUtilsTest {

	@Test
	public void anEscapedAmpersandStaysInsideItsValue() {
		Map<String, String> params = ParseUtils.parseUrlEncoded("address=0x1000%26size=4");
		assertEquals("0x1000&size=4", params.get("address"));
		assertNull("the escaped separator must not have become a parameter",
				params.get("size"));
	}

	@Test
	public void anEscapedEqualsStaysInsideItsValue() {
		Map<String, String> params = ParseUtils.parseUrlEncoded("comment=a%3Db");
		assertEquals("a=b", params.get("comment"));
	}

	@Test
	public void aValueIsDecodedExactlyOnce() {
		// %2520 is an escaped '%20'. Decoded once it is the text "%20";
		// decoded twice it collapses to a space, which is what used to happen.
		Map<String, String> params = ParseUtils.parseUrlEncoded("filter=%2520");
		assertEquals("%20", params.get("filter"));
	}

	@Test
	public void anUnescapedEqualsInsideAValueSurvives() {
		// Split on the FIRST '=' only: a value may legitimately contain more.
		Map<String, String> params = ParseUtils.parseUrlEncoded("prototype=int f(int a)=x");
		assertEquals("int f(int a)=x", params.get("prototype"));
	}

	@Test
	public void anEmptyValueIsKeptRatherThanDropped() {
		// The old parser required exactly two pieces, so `name=` vanished and
		// the handler could not tell "not given" from "given as empty".
		Map<String, String> params = ParseUtils.parseUrlEncoded("address=0x1000&name=");
		assertTrue(params.containsKey("name"));
		assertEquals("", params.get("name"));
	}

	@Test
	public void ordinaryParametersStillWork() {
		Map<String, String> params = ParseUtils.parseUrlEncoded("offset=10&limit=100");
		assertEquals("10", params.get("offset"));
		assertEquals("100", params.get("limit"));
	}

	@Test
	public void nothingAtAllIsNotAnError() {
		assertTrue(ParseUtils.parseUrlEncoded(null).isEmpty());
		assertTrue(ParseUtils.parseUrlEncoded("").isEmpty());
	}
}
