package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt16
import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt32
import ch.veehait.devicecheck.appattest.util.Extensions.toUUID
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectReader
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import java.io.ByteArrayInputStream
import java.util.UUID
import kotlin.experimental.and

data class AttestedCredentialData(
    val aaguid: UUID,
    val credentialId: ByteArray,
    val credentialPublicKey: LinkedHashMap<Any, Any>,
) {
    companion object {
        @Suppress("MagicNumber")
        fun parse(
            stream: ByteArrayInputStream,
            cborObjectReader: ObjectReader,
        ): AttestedCredentialData {
            val aaguid = stream.readNBytes(16)
            val credentialIdLength = stream.readNBytes(2).readAsUInt16()
            val credentialId = stream.readNBytes(credentialIdLength)
            val credentialPublicKey = cborObjectReader.readValue<LinkedHashMap<Any, Any>>(stream)

            return AttestedCredentialData(
                aaguid = aaguid.toUUID(),
                credentialId = credentialId,
                credentialPublicKey = credentialPublicKey,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestedCredentialData

        if (aaguid != other.aaguid) return false
        if (!credentialId.contentEquals(other.credentialId)) return false
        if (credentialPublicKey != other.credentialPublicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = aaguid.hashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + credentialPublicKey.hashCode()
        return result
    }
}

@Suppress("MagicNumber")
enum class AuthenticatorDataFlag(val bitmask: Byte) {
    UP(0x01),
    UV(0x04),
    AT(0x40),
    ED(-0x80);
}

/**
 * @property rpIdHash SHA-256 hash of the RP ID the credential is scoped to.
 * @property flags A list of [AuthenticatorDataFlag]s.
 * @property signCount The signature counter; is incremented for each generated assertion by some positive value.
 * @property attestedCredentialData A variable-length byte array added to the authenticator data when generating an
 *   attestation object.
 * @property extensions WebAuthn Extensions.
 */
data class AuthenticatorData(
    val rpIdHash: ByteArray,
    val flags: List<AuthenticatorDataFlag>,
    val signCount: Long,
    val attestedCredentialData: AttestedCredentialData?,
    val extensions: LinkedHashMap<Any, Any>?,
) {
    companion object {
        const val FLAGS_INDEX: Int = 32

        private val cborObjectReader = ObjectMapper(CBORFactory()).readerForMapOf(Any::class.java)

        @Suppress("MagicNumber")
        fun parse(
            data: ByteArray,
            cborObjectReader: ObjectReader = AuthenticatorData.cborObjectReader,
        ): AuthenticatorData = data.inputStream().use { stream ->
            val rpIdHash = stream.readNBytes(32)
            val flagsByte = stream.readNBytes(1).first()
            val flags = AuthenticatorDataFlag.values().filter { (flagsByte and it.bitmask).toInt() != 0 }
            val signCount = stream.readNBytes(4).readAsUInt32()

            val attestedCredentialData = if (AuthenticatorDataFlag.AT in flags) {
                AttestedCredentialData.parse(stream, cborObjectReader)
            } else null

            val extensions = if (AuthenticatorDataFlag.ED in flags) {
                cborObjectReader.readValue<LinkedHashMap<Any, Any>>(stream)
            } else null

            AuthenticatorData(
                rpIdHash = rpIdHash,
                flags = flags,
                signCount = signCount,
                attestedCredentialData = attestedCredentialData,
                extensions = extensions,
            )
        }
    }

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

    override fun hashCode(): Int {
        var result = rpIdHash.contentHashCode()
        result = 31 * result + flags.hashCode()
        result = 31 * result + signCount.hashCode()
        result = 31 * result + (attestedCredentialData?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }
}
