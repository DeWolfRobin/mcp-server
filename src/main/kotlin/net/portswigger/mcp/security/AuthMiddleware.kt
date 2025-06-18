package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.util.*

class AuthMiddleware(
    private val authConfig: AuthConfig,
    private val logging: Logging
) {

    companion object {
        private const val BEARER_PREFIX = "Bearer "
        const val API_KEY_HEADER = "X-API-Key"
        const val CLIENT_ID_HEADER = "X-Client-ID"
        const val CLIENT_SECRET_HEADER = "X-Client-Secret"
        private const val TOKEN_ENDPOINT = "/auth/token"
        private const val AUTH_ERROR_MESSAGE =
            "Authentication required. Use 'Authorization: Bearer <token>' or 'X-API-Key: <token>' header."
    }

    suspend fun intercept(call: ApplicationCall, next: suspend () -> Unit) {
        if (!authConfig.authenticationEnabled) {
            next()
            return
        }

        val token = extractToken(call)
        if (token != null) {
            val authToken = authConfig.validateToken(token)
            if (authToken != null) {
                call.attributes.put(AuthContextKey, AuthContext(authToken))
                next()
                return
            }
        }

        val clientCredentials = extractClientCredentials(call)
        if (clientCredentials != null) {
            val (clientId, clientSecret) = clientCredentials
            logging.logToOutput("Attempting client credentials authentication for: $clientId")
            val client = authConfig.getClientCredentials(clientId)
            if (client != null && client.enabled && client.clientSecret == clientSecret) {
                logging.logToOutput("Client credentials authentication successful for: $clientId")
                val now = System.currentTimeMillis() / 1000
                val tempToken = AuthToken(
                    token = "client:$clientId",
                    clientId = clientId,
                    createdAt = now,
                    expiresAt = now + (24 * 3600L)
                )
                call.attributes.put(AuthContextKey, AuthContext(tempToken))
                next()
                return
            } else {
                logging.logToError("Client credentials authentication failed for: $clientId (client found: ${client != null}, enabled: ${client?.enabled})")
            }
        }

        if (call.request.uri == TOKEN_ENDPOINT && call.request.httpMethod == HttpMethod.Post) {
            next()
            return
        }

        logging.logToError("Authentication required for ${call.request.uri}")
        call.respond(HttpStatusCode.Unauthorized, AUTH_ERROR_MESSAGE)
    }

    private fun extractToken(call: ApplicationCall): String? {
        val authHeader = call.request.headers[HttpHeaders.Authorization]
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length).trim()
        }

        val apiKeyHeader = call.request.headers[API_KEY_HEADER]
        if (apiKeyHeader != null) {
            return apiKeyHeader.trim()
        }

        return null
    }

    private fun extractClientCredentials(call: ApplicationCall): Pair<String, String>? {
        val clientId = call.request.headers[CLIENT_ID_HEADER]
        val clientSecret = call.request.headers[CLIENT_SECRET_HEADER]

        return if (clientId != null && clientSecret != null) {
            Pair(clientId, clientSecret)
        } else null
    }
}

data class AuthContext(
    val token: AuthToken
)

val AuthContextKey = AttributeKey<AuthContext>("AuthContext")

suspend fun handleTokenRequest(call: ApplicationCall, authConfig: AuthConfig, logging: Logging) {
    try {
        val clientId = call.request.headers[AuthMiddleware.CLIENT_ID_HEADER]
        val clientSecret = call.request.headers[AuthMiddleware.CLIENT_SECRET_HEADER]

        if (clientId.isNullOrBlank() || clientSecret.isNullOrBlank()) {
            call.respond(
                HttpStatusCode.BadRequest,
                "Client ID and secret are required in headers: ${AuthMiddleware.CLIENT_ID_HEADER}, ${AuthMiddleware.CLIENT_SECRET_HEADER}"
            )
            return
        }

        val token = authConfig.generateToken(clientId, clientSecret)
        if (token != null) {
            call.respond(
                HttpStatusCode.OK,
                mapOf(
                    "access_token" to token.token,
                    "token_type" to "Bearer",
                    "created_at" to token.createdAt
                )
            )
        } else {
            logging.logToError("Token generation failed for client: $clientId")
            call.respond(
                HttpStatusCode.Unauthorized,
                "Invalid client credentials or client disabled"
            )
        }
    } catch (e: Exception) {
        logging.logToError("Token generation failed: ${e.message}")
        call.respond(
            HttpStatusCode.InternalServerError,
            "Token generation failed"
        )
    }
}