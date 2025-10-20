package net.portswigger.mcp.tools

/**
 * Simple in-memory cache for HTTP request results to help prevent
 * the language model from issuing the same request repeatedly.
 */
object HttpResponseCache {
    private data class Entry(val timestamp: Long, val response: String)
    private const val MAX_ENTRIES = 50
    private const val EXPIRY_MS = 5 * 60 * 1000L // 5 minutes
    private val cache = LinkedHashMap<String, Entry>()

    @Synchronized
    fun get(key: String): String? {
        val entry = cache[key] ?: return null
        if (System.currentTimeMillis() - entry.timestamp > EXPIRY_MS) {
            cache.remove(key)
            return null
        }
        return entry.response
    }

    @Synchronized
    fun put(key: String, response: String) {
        if (cache.size >= MAX_ENTRIES) {
            val oldestKey = cache.keys.firstOrNull()
            if (oldestKey != null) cache.remove(oldestKey)
        }
        cache[key] = Entry(System.currentTimeMillis(), response)
    }
}
