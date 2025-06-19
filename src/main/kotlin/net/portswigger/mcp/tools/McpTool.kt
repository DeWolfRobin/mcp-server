package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import net.portswigger.mcp.tools.ToolRegistry
import kotlin.experimental.ExperimentalTypeInference

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    if (!ToolRegistry.isToolAllowed(toolName)) return

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            if (!ToolRegistry.incrementCallCount(toolName)) {
                return@addTool CallToolResult(
                    content = listOf(TextContent("Rate limit exceeded")),
                    isError = true,
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            }

            try {
                val args = Json.decodeFromJsonElement(
                    I::class.serializer(),
                    request.arguments
                )
                CallToolResult(
                    content = execute(args),
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            } catch (_: SerializationException) {
                CallToolResult(
                    content = listOf(TextContent("Error: invalid parameters")),
                    isError = true,
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("Error: ${e.message}")),
                    isError = true,
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        when {
            offset >= items.size -> {
                "Reached end of items"
            }

            else -> {
                val upperLimit = (offset + count).coerceAtMost(items.size)

                items.subList(offset, upperLimit)
                    .joinToString(separator = "\n\n", transform = mapper)
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val seq = execute(this)
        val paginated = seq.drop(offset).take(count).toList()

        if (paginated.isEmpty()) {
            listOf(TextContent("Reached end of items"))
        } else {
            listOf(TextContent(paginated.joinToString(separator = "\n\n")))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    if (!ToolRegistry.isToolAllowed(name)) return

    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            if (!ToolRegistry.incrementCallCount(name)) {
                return@addTool CallToolResult(
                    content = listOf(TextContent("Rate limit exceeded")),
                    isError = true,
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            }

            CallToolResult(
                content = execute(),
                _meta = buildJsonObject { put("tool_response", true) }
            )
        }
    )
}
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    if (!ToolRegistry.isToolAllowed(name)) return

    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            if (!ToolRegistry.incrementCallCount(name)) {
                return@addTool CallToolResult(
                    content = listOf(TextContent("Rate limit exceeded")),
                    isError = true,
                    _meta = buildJsonObject { put("tool_response", true) }
                )
            }

            CallToolResult(
                content = listOf(TextContent(execute())),
                _meta = buildJsonObject { put("tool_response", true) }
            )
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}

