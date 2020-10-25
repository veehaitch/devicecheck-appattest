package ch.veehait.devicecheck.appattest.receipt

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.codec.binary.Base64
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Clock

interface AppleJwsGenerator {
    val appleTeamIdentifier: String
    val keyIdentifier: String
    val privateKey: PrivateKey

    /**
     * Generate a JWT signed with the [privateKey] with [keyIdentifier] and issuer [appleTeamIdentifier]
     *
     * @return A token suitable for HTTP bearer authorization
     */
    fun issueToken(): String
}

internal class AppleJwsGeneratorImpl(
    override val appleTeamIdentifier: String,
    override val keyIdentifier: String,
    privateKeyPem: String,
    private val jsonObjectMapper: ObjectMapper = ObjectMapper(JsonFactory()),
    private val clock: Clock = Clock.systemUTC(),
) : AppleJwsGenerator {
    private val signatureInstance = Signature.getInstance("SHA256withECDSAinP1363Format")

    private fun parsePrivateKey(pem: String): PrivateKey = pem
        .replace(Regex("-----(BEGIN|END) PRIVATE KEY-----"), "")
        .trim()
        .let(Base64::decodeBase64)
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("EC")::generatePrivate)

    override val privateKey: PrivateKey = parsePrivateKey(privateKeyPem)

    override fun issueToken(): String {
        val header = mapOf(
            "alg" to "ES256",
            "kid" to keyIdentifier,
        ).let(jsonObjectMapper::writeValueAsBytes).let(Base64::encodeBase64URLSafeString)

        val payload = mapOf(
            "iss" to appleTeamIdentifier,
            "iat" to clock.instant().epochSecond
        ).let(jsonObjectMapper::writeValueAsBytes).let(Base64::encodeBase64URLSafeString)

        val signature = signatureInstance.run {
            initSign(privateKey)
            update("$header.$payload".toByteArray())
            sign()
        }.let(Base64::encodeBase64URLSafeString)

        return "$header.$payload.$signature"
    }
}
