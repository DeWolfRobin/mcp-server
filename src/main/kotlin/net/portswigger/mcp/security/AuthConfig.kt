package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.boolean
import net.portswigger.mcp.config.int
import net.portswigger.mcp.config.string
import java.security.SecureRandom
import java.time.Instant
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

@Serializable
data class AuthToken(
    val token: String,
    val clientId: String,
    val createdAt: Long,
    val expiresAt: Long
)

@Serializable
data class ClientCredentials(
    val clientId: String,
    val clientSecret: String,
    val name: String,
    val createdAt: Long,
    val enabled: Boolean = true
)

class AuthConfig(storage: PersistedObject, private val logging: Logging) {

    companion object {
        private const val DEFAULT_MAX_TOKENS_PER_CLIENT = 10
        private const val DEFAULT_TOKEN_EXPIRY_HOURS = 24 * 7
        private const val CLIENT_ID_PREFIX = "mcp_"
        private const val CLIENT_ID_LENGTH = 16
        private const val CLIENT_SECRET_LENGTH = 32
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding"
        private const val KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val RANDOM_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        private const val PBKDF2_ITERATIONS = 100000
        private const val AES_KEY_LENGTH = 256
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }

    var authenticationEnabled by storage.boolean(false)
    var maxTokensPerClient by storage.int(DEFAULT_MAX_TOKENS_PER_CLIENT)
    var tokenExpiryHours by storage.int(DEFAULT_TOKEN_EXPIRY_HOURS)

    private var _clientCredentialsJson by storage.string("{}")
    private var _activeTokensJson by storage.string("{}")
    private var _encryptedSecretKey by storage.string("")
    private var _keySalt by storage.string("")
    private var _keyDerivationSeed by storage.string("")
    private var _masterKeyDerivationKey by storage.string("")  // SECURITY FIX: Secure master key for derivation

    private val secureRandom = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true }

    init {
        if (_masterKeyDerivationKey.isEmpty()) {
            generateSecureMasterKeyDerivationKey()
        }
        
        if (_encryptedSecretKey.isEmpty() || _keySalt.isEmpty() || _keyDerivationSeed.isEmpty()) {
            generateAndStoreSecretKey()
        }

        cleanupExpiredTokens()
    }

    private fun generateSecureMasterKeyDerivationKey() {
        val masterKeyBytes = ByteArray(64)
        secureRandom.nextBytes(masterKeyBytes)

        _masterKeyDerivationKey = Base64.getEncoder().encodeToString(masterKeyBytes)

        logging.logToOutput("Generated secure master key derivation key")
    }

    private fun generateAndStoreSecretKey() {
        val keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM)
        keyGen.init(256)
        val secretKey = keyGen.generateKey()

        val salt = ByteArray(32)
        secureRandom.nextBytes(salt)
        _keySalt = Base64.getEncoder().encodeToString(salt)

        val seed = generateRandomString(32)
        _keyDerivationSeed = seed

        val encryptedKey = encryptSecretKey(secretKey.encoded, salt, seed)
        _encryptedSecretKey = Base64.getEncoder().encodeToString(encryptedKey)

        logging.logToOutput("Generated and encrypted new master secret key")
    }

    private fun generateSecureKeyDerivationPassword(seed: String): String {
        val masterKeyBytes = Base64.getDecoder().decode(_masterKeyDerivationKey)
        val applicationSalt = "mcp-auth-secure-kdf-v2"

        val hmac = Mac.getInstance("HmacSHA256")
        val keySpec = SecretKeySpec(masterKeyBytes, "HmacSHA256")
        hmac.init(keySpec)

        val keyMaterial = "${applicationSalt}:${seed}".toByteArray()
        val derivedKey = hmac.doFinal(keyMaterial)

        return Base64.getEncoder().encodeToString(derivedKey)
    }

    private fun encryptSecretKey(keyBytes: ByteArray, salt: ByteArray, seed: String): ByteArray {
        val password = generateSecureKeyDerivationPassword(seed).toCharArray()

        val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM)
        val derivedKey = factory.generateSecret(spec)
        val secretKey = SecretKeySpec(derivedKey.encoded, "AES")

        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encryptedData = cipher.doFinal(keyBytes)

        password.fill('0')
        
        return iv + encryptedData
    }

    private fun decryptSecretKey(): ByteArray {
        val salt = Base64.getDecoder().decode(_keySalt)
        val encryptedData = Base64.getDecoder().decode(_encryptedSecretKey)
        val seed = _keyDerivationSeed

        val password = generateSecureKeyDerivationPassword(seed).toCharArray()

        val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM)
        val derivedKey = factory.generateSecret(spec)
        val secretKey = SecretKeySpec(derivedKey.encoded, "AES")

        val iv = encryptedData.sliceArray(0..GCM_IV_LENGTH - 1)
        val encrypted = encryptedData.sliceArray(GCM_IV_LENGTH until encryptedData.size)

        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val result = cipher.doFinal(encrypted)

        password.fill('0')

        return result
    }

    fun generateClientCredentials(name: String): ClientCredentials {
        require(name.isNotBlank()) { "Client name cannot be blank" }

        val clientId = CLIENT_ID_PREFIX + generateRandomString(CLIENT_ID_LENGTH)
        val clientSecret = generateRandomString(CLIENT_SECRET_LENGTH)

        val credentials = ClientCredentials(
            clientId = clientId,
            clientSecret = clientSecret,
            name = name,
            createdAt = Instant.now().epochSecond,
            enabled = true
        )

        saveClientCredentials(credentials)
        logging.logToOutput("Generated new client credentials for: $name (ID: $clientId)")
        return credentials
    }

    fun generateToken(clientId: String, clientSecret: String): AuthToken? {
        val client = getClientCredentials(clientId)
        if (client?.enabled != true || client.clientSecret != clientSecret) {
            logging.logToError("Authentication failed for client: $clientId")
            return null
        }

        val activeTokens = getActiveTokensForClient(clientId)
        if (activeTokens.size >= maxTokensPerClient) {
            logging.logToError("Token limit exceeded for client: $clientId ($maxTokensPerClient max)")
            return null
        }

        val tokenValue = generateSecureToken(clientId)

        val now = Instant.now().epochSecond
        val expiresAt = now + (tokenExpiryHours * 3600L)

        val token = AuthToken(
            token = tokenValue,
            clientId = clientId,
            createdAt = now,
            expiresAt = expiresAt
        )

        saveToken(token)
        logging.logToOutput("Generated new token for client: $clientId")
        return token
    }

    fun validateToken(tokenValue: String): AuthToken? {
        val token = getToken(tokenValue) ?: return null

        val now = Instant.now().epochSecond
        if (token.expiresAt <= now) {
            removeToken(tokenValue)
            logging.logToOutput("Removed expired token for client: ${token.clientId}")
            return null
        }

        val client = getClientCredentials(token.clientId)
        if (client?.enabled != true) {
            removeToken(tokenValue)
            logging.logToOutput("Removed token for disabled client: ${token.clientId}")
            return null
        }

        return token
    }

    fun revokeToken(tokenValue: String): Boolean {
        val success = removeToken(tokenValue)
        if (success) {
            logging.logToOutput("Token revoked successfully")
        }
        return success
    }

    fun revokeAllTokensForClient(clientId: String) {
        val tokens = getActiveTokensForClient(clientId)
        tokens.forEach { removeToken(it.token) }
        if (tokens.isNotEmpty()) {
            logging.logToOutput("Revoked ${tokens.size} tokens for client: $clientId")
        }
    }

    fun deleteClient(clientId: String): Boolean {
        val clients = getAllClientCredentials().toMutableMap()
        val removed = clients.remove(clientId) != null
        if (removed) {
            _clientCredentialsJson = json.encodeToString(clients)
            revokeAllTokensForClient(clientId)
            logging.logToOutput("Deleted client: $clientId")
        }
        return removed
    }

    fun listClients(): List<ClientCredentials> {
        return getAllClientCredentials().values.sortedByDescending { it.createdAt }
    }

    fun listActiveTokens(): List<AuthToken> {
        val now = Instant.now().epochSecond
        return getAllTokens().values
            .filter { it.expiresAt > now }
            .sortedByDescending { it.createdAt }
    }

    fun cleanupExpiredTokens(): Int {
        val now = Instant.now().epochSecond
        val allTokens = getAllTokens().toMutableMap()
        val expiredTokens = allTokens.filter { it.value.expiresAt <= now }

        expiredTokens.keys.forEach { allTokens.remove(it) }

        if (expiredTokens.isNotEmpty()) {
            _activeTokensJson = json.encodeToString(allTokens)
            logging.logToOutput("Cleaned up ${expiredTokens.size} expired tokens")
        }

        return expiredTokens.size
    }

    private fun generateSecureToken(clientId: String): String {
        val payload = "$clientId:${Instant.now().epochSecond}:${generateRandomString(16)}"
        val hmac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKeyBytes = decryptSecretKey()
        val secretKeySpec = SecretKeySpec(secretKeyBytes, HMAC_ALGORITHM)
        hmac.init(secretKeySpec)
        val signature = Base64.getEncoder().encodeToString(hmac.doFinal(payload.toByteArray()))
        return Base64.getEncoder().encodeToString("$payload:$signature".toByteArray())
    }

    private fun generateRandomString(length: Int): String {
        return (1..length)
            .map { RANDOM_CHARS[secureRandom.nextInt(RANDOM_CHARS.length)] }
            .joinToString("")
    }

    private fun saveClientCredentials(credentials: ClientCredentials) {
        val clients = getAllClientCredentials().toMutableMap()
        clients[credentials.clientId] = credentials
        _clientCredentialsJson = json.encodeToString(clients)
    }

    fun getClientCredentials(clientId: String): ClientCredentials? {
        return getAllClientCredentials()[clientId]
    }

    private fun getAllClientCredentials(): Map<String, ClientCredentials> {
        return try {
            if (_clientCredentialsJson.isBlank() || _clientCredentialsJson == "{}") {
                emptyMap()
            } else {
                json.decodeFromString<Map<String, ClientCredentials>>(_clientCredentialsJson)
            }
        } catch (e: Exception) {
            logging.logToError("Failed to parse client credentials: ${e.message}")
            emptyMap()
        }
    }

    private fun saveToken(token: AuthToken) {
        val tokens = getAllTokens().toMutableMap()
        tokens[token.token] = token
        _activeTokensJson = json.encodeToString(tokens)
    }

    private fun getToken(tokenValue: String): AuthToken? {
        return getAllTokens()[tokenValue]
    }

    private fun removeToken(tokenValue: String): Boolean {
        val tokens = getAllTokens().toMutableMap()
        val removed = tokens.remove(tokenValue) != null
        if (removed) {
            _activeTokensJson = json.encodeToString(tokens)
        }
        return removed
    }

    private fun getAllTokens(): Map<String, AuthToken> {
        return try {
            if (_activeTokensJson.isBlank() || _activeTokensJson == "{}") {
                emptyMap()
            } else {
                json.decodeFromString<Map<String, AuthToken>>(_activeTokensJson)
            }
        } catch (e: Exception) {
            logging.logToError("Failed to parse active tokens: ${e.message}")
            emptyMap()
        }
    }

    private fun getActiveTokensForClient(clientId: String): List<AuthToken> {
        return getAllTokens().values.filter { it.clientId == clientId }
    }

}