package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt16
import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt32
import ch.veehait.devicecheck.appattest.util.Extensions.toUUID
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectReader
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.io.ByteArrayInputStream
import java.util.UUID
import javax.annotation.processing.Generated
import kotlin.experimental.and

internal typealias AuthenticatorDataExtensions = LinkedHashMap<Any, Any>
internal typealias CredentialPublicKey = LinkedHashMap<Any, Any>

/**
 * Attested credential data is a variable-length byte array added to the authenticator data when generating an
 * attestation object for a given credential.
 *
 * @param aaguid The AAGUID of the authenticator.
 * @param credentialId A probabilistically-unique byte sequence identifying a public key credential source and its
 *   authentication assertions.
 * @param credentialPublicKey The credential public key encoded in COSE_Key format.
 * @see [Web Authentication: Attested Credential Data](https://www.w3.org/TR/webauthn/#attested-credential-data)
 */
data class AttestedCredentialData(
    val aaguid: UUID,
    val credentialId: ByteArray,
    val credentialPublicKey: CredentialPublicKey
) {
    companion object {
        @JvmStatic
        @Suppress("MagicNumber")
        fun parse(
            stream: ByteArrayInputStream,
            cborObjectReader: ObjectReader
        ): Pair<AttestedCredentialData, AuthenticatorDataExtensions?> {
            val aaguid = stream.readNBytes(16)
            val credentialIdLength = stream.readNBytes(2).readAsUInt16()
            val credentialId = stream.readNBytes(credentialIdLength)
            val mappingIterator = cborObjectReader.readValues<LinkedHashMap<Any, Any>>(stream)

            val credentialPublicKey = mappingIterator.nextValue()
            val extensions: LinkedHashMap<Any, Any>? = if (mappingIterator.hasNextValue()) {
                mappingIterator.nextValue()
            } else {
                null
            }

            return Pair(
                AttestedCredentialData(
                    aaguid = aaguid.toUUID(),
                    credentialId = credentialId,
                    credentialPublicKey = credentialPublicKey
                ),
                extensions
            )
        }
    }

    @Generated
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestedCredentialData

        if (aaguid != other.aaguid) return false
        if (!credentialId.contentEquals(other.credentialId)) return false
        if (credentialPublicKey != other.credentialPublicKey) return false

        return true
    }

    @Generated
    override fun hashCode(): Int {
        var result = aaguid.hashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + credentialPublicKey.hashCode()
        return result
    }
}

@Suppress("MagicNumber")
enum class AuthenticatorDataFlag(val bitmask: Byte) {
    /** Bit 0: User Present (UP) result */
    UP(0x01),

    /** Bit 2: User Verified (UV) result */
    UV(0x04),

    /** Bit 6: Attested credential data included (AT) */
    AT(0x40),

    /** Bit 7: Extension data included (ED) */
    ED(-0x80);
}

/**
 * The authenticator data structure encodes contextual bindings made by the authenticator.
 *
 * @property rpIdHash SHA-256 hash of the RP ID the credential is scoped to.
 * @property flags A list of [AuthenticatorDataFlag]s.
 * @property signCount The signature counter; is incremented for each generated assertion by some positive value.
 * @property attestedCredentialData A variable-length byte array added to the authenticator data when generating an
 *   attestation object.
 * @property extensions WebAuthn Extensions.
 * @see [Web Authentication: Authenticator Data](https://www.w3.org/TR/webauthn/#sec-authenticator-data)
 */
data class AuthenticatorData(
    val rpIdHash: ByteArray,
    val flags: List<AuthenticatorDataFlag>,
    val signCount: Long,
    val attestedCredentialData: AttestedCredentialData?,
    val extensions: LinkedHashMap<Any, Any>?
) {
    companion object {
        const val FLAGS_INDEX: Int = 32

        private val cborObjectReader = ObjectMapper(CBORFactory())
            .disable(JsonParser.Feature.AUTO_CLOSE_SOURCE)
            .readerForMapOf(Any::class.java)

        @JvmStatic
        @Suppress("MagicNumber")
        fun parse(
            data: ByteArray,
            cborObjectReader: ObjectReader = AuthenticatorData.cborObjectReader
        ): AuthenticatorData = data.inputStream().use { stream ->
            val rpIdHash = stream.readNBytes(32)
            val flagsByte = stream.readNBytes(1).first()
            val flags = AuthenticatorDataFlag.values().filter { (flagsByte and it.bitmask).toInt() != 0 }
            val signCount = stream.readNBytes(4).readAsUInt32()

            val (attestedCredentialData, extensions) = when {
                AuthenticatorDataFlag.AT !in flags && AuthenticatorDataFlag.ED in flags -> {
                    Pair(null, cborObjectReader.readValue<LinkedHashMap<Any, Any>>(stream))
                }
                AuthenticatorDataFlag.AT !in flags && AuthenticatorDataFlag.ED !in flags -> {
                    Pair(null, null)
                }
                else -> AttestedCredentialData.parse(stream, cborObjectReader)
            }

            AuthenticatorData(
                rpIdHash = rpIdHash,
                flags = flags,
                signCount = signCount,
                attestedCredentialData = attestedCredentialData,
                extensions = extensions
            )
        }
    }

    @Generated
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorData

        if (!rpIdHash.contentEquals(other.rpIdHash)) return false
        if (flags != other.flags) return false
        if (signCount != other.signCount) return false
        if (attestedCredentialData != other.attestedCredentialData) return false
        if (extensions != other.extensions) return false

        return true
    }

    @Generated
    override fun hashCode(): Int {
        var result = rpIdHash.contentHashCode()
        result = 31 * result + flags.hashCode()
        result = 31 * result + signCount.hashCode()
        result = 31 * result + (attestedCredentialData?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }
}
