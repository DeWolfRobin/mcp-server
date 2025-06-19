package net.portswigger.mcp.logging

import burp.api.montoya.logging.Logging

class UiLogging(private val delegate: Logging) : Logging by delegate {
    override fun logToOutput(message: String) {
        delegate.logToOutput(message)
        ExtensionLogger.log(message)
    }

    override fun logToError(message: String) {
        delegate.logToError(message)
        ExtensionLogger.log("ERROR: $message")
    }

    override fun logToError(throwable: Throwable) {
        delegate.logToError(throwable)
        ExtensionLogger.log("ERROR: ${throwable.message ?: throwable.javaClass.simpleName}")
    }
}
