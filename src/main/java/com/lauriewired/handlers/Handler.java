package com.lauriewired.handlers;

import com.lauriewired.util.Transactions;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

/**
 * Abstract class representing a handler for HTTP requests in a Ghidra
 * PluginTool.
 * Subclasses must implement the handle method to define how requests are
 * processed.
 */
public abstract class Handler {
	/** The PluginTool instance this handler is associated with. */
	protected final PluginTool tool;

	/** The path this handler will respond to. */
	protected final String path;

	/**
	 * Which session the request currently being handled belongs to.
	 *
	 * A plain field is enough: each server dispatches its requests one at a
	 * time (the plugin leaves the executor null on purpose) and each server
	 * builds its own handler objects, so no two requests are ever inside the
	 * same Handler at once. ServerIsSerialTest pins that assumption.
	 */
	private volatile String sessionTag = "";

	/**
	 * Constructs a new Handler with the specified PluginTool and path.
	 *
	 * @param tool the PluginTool instance this handler is associated with
	 * @param path the path this handler will respond to
	 */
	protected Handler(PluginTool tool, String path) {
		this.tool = tool;
		this.path = path;
	}

	/**
	 * Gets the path this handler will respond to.
	 *
	 * @return the path
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Records which session the request about to be handled belongs to.
	 *
	 * @param tag the caller's session, or null if it named none
	 */
	public final void beginRequest(String tag) {
		this.sessionTag = tag == null ? "" : tag;
	}

	/** Forgets the session, once the request is done with. */
	public final void endRequest() {
		this.sessionTag = "";
	}

	/**
	 * The name to record a Ghidra transaction under, naming the session that
	 * asked for it. Every transaction opened by a handler must go through this:
	 * a generic name throws away the only record of who acted.
	 *
	 * @param transactionName what the transaction does, e.g. "Create Function"
	 * @return that name, with the calling session appended when one is known
	 */
	protected final String tx(String transactionName) {
		return Transactions.name(transactionName, sessionTag);
	}

	/**
	 * Handles an HTTP request.
	 * Subclasses must implement this method to define how requests are
	 * processed.
	 *
	 * @param exchange the HttpExchange object representing the HTTP request
	 * @throws Exception if an error occurs while handling the request
	 */
	public abstract void handle(HttpExchange exchange) throws Exception;
}
