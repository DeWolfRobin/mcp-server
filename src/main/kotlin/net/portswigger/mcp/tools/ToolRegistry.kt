package net.portswigger.mcp.tools

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Simple registry to manage which tools are active and basic rate limiting.
 */
object ToolRegistry {
    private val allowedTools: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val callCounts: MutableMap<String, AtomicInteger> = ConcurrentHashMap()
    @Volatile
    var maxCallsPerMinute: Int = 60

    fun setAllowedTools(tools: Collection<String>) {
        allowedTools.clear()
        allowedTools.addAll(tools)
    }

    fun isToolAllowed(name: String): Boolean {
        return allowedTools.isEmpty() || allowedTools.contains(name)
    }

    fun incrementCallCount(name: String): Boolean {
        val nowMinute = System.currentTimeMillis() / 60000
        val key = "$name:$nowMinute"
        val count = callCounts.computeIfAbsent(key) { AtomicInteger(0) }.incrementAndGet()
        return count <= maxCallsPerMinute
    }
}
