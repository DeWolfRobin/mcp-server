package net.portswigger.mcp.logging

import java.lang.ref.WeakReference
import java.util.concurrent.CopyOnWriteArrayList

fun interface LogListenerHandle { fun remove() }

object ExtensionLogger {
    private val logs = CopyOnWriteArrayList<String>()
    private val listeners = CopyOnWriteArrayList<WeakReference<(String) -> Unit>>()

    fun log(message: String) {
        logs.add(message)
        val iterator = listeners.iterator()
        while (iterator.hasNext()) {
            val ref = iterator.next()
            val listener = ref.get()
            if (listener == null) {
                listeners.remove(ref)
            } else {
                try {
                    listener(message)
                } catch (_: Exception) {
                }
            }
        }
    }

    fun logs(): List<String> = logs.toList()

    fun addListener(listener: (String) -> Unit): LogListenerHandle {
        val ref = WeakReference(listener)
        listeners.add(ref)
        return LogListenerHandle { listeners.remove(ref) }
    }
}
