package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import io.modelcontextprotocol.kotlin.sdk.CallToolResultBase
import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.decodeFromString
import net.portswigger.mcp.tools.StructuredHttpResponse
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.IssueDetails
import net.portswigger.mcp.schema.AuditIssueSeverity
import net.portswigger.mcp.schema.AuditIssueConfidence
import net.portswigger.mcp.schema.AuditIssueDefinition
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.server.KtorServerManager
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import javax.swing.JTextArea

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireHistoryAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResultBase?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any(), any()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpRequestResponse.response() } returns httpResponse
            every { httpResponse.httpVersion() } returns "HTTP/1.1"
            every { httpResponse.statusCode() } returns 200
            every { httpResponse.reasonPhrase() } returns "OK"
            every { httpResponse.headers() } returns listOf(HttpHeader.httpHeader("Content-Type", "text/plain"))
            every { httpResponse.bodyToString() } returns "Response body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpRequestResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"),
                    "Expected success response but got error: $text")
                val structured = Json.decodeFromString<StructuredHttpResponse>(text)
                assertEquals("HTTP/1.1 200 OK", structured.statusLine)
                assertEquals(mapOf("Content-Type" to "text/plain"), structured.headers)
                assertEquals("Response body", structured.body)
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.http() } returns httpService
            every { httpRequestResponse.response() } returns httpResponse
            every { httpResponse.httpVersion() } returns "HTTP/2"
            every { httpResponse.statusCode() } returns 200
            every { httpResponse.reasonPhrase() } returns "OK"
            every { httpResponse.headers() } returns listOf(HttpHeader.httpHeader("Content-Type", "text/plain"))
            every { httpResponse.bodyToString() } returns "Response body"
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpRequestResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"),
                    "Expected success response but got error: $text")
                val structured = Json.decodeFromString<StructuredHttpResponse>(text)
                assertEquals("HTTP/2 200 OK", structured.statusLine)
                assertEquals(mapOf("Content-Type" to "text/plain"), structured.headers)
                assertEquals("Response body", structured.body)
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpRequestResponse.response() } returns httpResponse
            every { httpResponse.httpVersion() } returns "HTTP/2"
            every { httpResponse.statusCode() } returns 200
            every { httpResponse.reasonPhrase() } returns "OK"
            every { httpResponse.headers() } returns emptyList()
            every { httpResponse.bodyToString() } returns ""
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpRequestResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i], 
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }
    }
    
    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            
            every { proxyHistory[0].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 1 notes"
            )
            every { proxyHistory[1].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item2 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 2 notes"
            )
            every { proxyHistory[2].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item3 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 3 notes"
            )
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("GET /item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }

        @Test
        fun `get scanner issues for url should paginate properly`() {
            val siteMap = mockk<burp.api.montoya.sitemap.SiteMap>()
            val issue1 = mockk<burp.api.montoya.scanner.audit.issues.AuditIssue>()
            val issue2 = mockk<burp.api.montoya.scanner.audit.issues.AuditIssue>()
            val issue3 = mockk<burp.api.montoya.scanner.audit.issues.AuditIssue>()

            every { api.siteMap() } returns siteMap
            every { siteMap.issues(SiteMapFilter.prefixFilter("https://example.com")) } returns listOf(issue1, issue2, issue3)

            mockkStatic("net.portswigger.mcp.schema.SerializationKt")

            every { issue1.toSerializableForm() } returns IssueDetails(
                name = "Issue1",
                detail = null,
                remediation = null,
                httpService = null,
                baseUrl = "https://example.com",
                severity = AuditIssueSeverity.HIGH,
                confidence = AuditIssueConfidence.CERTAIN,
                requestResponses = emptyList(),
                collaboratorInteractions = emptyList(),
                definition = AuditIssueDefinition(
                    id = "1",
                    background = null,
                    remediation = null,
                    typeIndex = 0
                )
            )
            every { issue2.toSerializableForm() } returns IssueDetails(
                name = "Issue2",
                detail = null,
                remediation = null,
                httpService = null,
                baseUrl = "https://example.com",
                severity = AuditIssueSeverity.MEDIUM,
                confidence = AuditIssueConfidence.CERTAIN,
                requestResponses = emptyList(),
                collaboratorInteractions = emptyList(),
                definition = AuditIssueDefinition(
                    id = "2",
                    background = null,
                    remediation = null,
                    typeIndex = 0
                )
            )
            every { issue3.toSerializableForm() } returns IssueDetails(
                name = "Issue3",
                detail = null,
                remediation = null,
                httpService = null,
                baseUrl = "https://example.com",
                severity = AuditIssueSeverity.LOW,
                confidence = AuditIssueConfidence.CERTAIN,
                requestResponses = emptyList(),
                collaboratorInteractions = emptyList(),
                definition = AuditIssueDefinition(
                    id = "3",
                    background = null,
                    remediation = null,
                    typeIndex = 0
                )
            )

            runBlocking {
                val result1 = client.callTool(
                    "get_scanner_issues_for_url", mapOf(
                        "url" to "https://example.com",
                        "count" to 2,
                        "offset" to 0
                    )
                )

                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("Issue1"))
                assertTrue(text1.contains("Issue2"))
                assertFalse(text1.contains("Issue3"))

                val result2 = client.callTool(
                    "get_scanner_issues_for_url", mapOf(
                        "url" to "https://example.com",
                        "count" to 2,
                        "offset" to 2
                    )
                )

                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("Issue3"))

                val result3 = client.callTool(
                    "get_scanner_issues_for_url", mapOf(
                        "url" to "https://example.com",
                        "count" to 2,
                        "offset" to 3
                    )
                )

                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }

            verify(exactly = 1) { siteMap.issues(SiteMapFilter.prefixFilter("https://example.com")) }
        }
    }
    
    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "get_scanner_issues_for_url" })
        }
        
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        
        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
            
            client.connectToServer("http://127.0.0.1:${testPort}")
            
            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "get_scanner_issues_for_url" })
        }
    }
}