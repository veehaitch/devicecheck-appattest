package devicecheck.appattest

import com.webauthn4j.data.attestation.authenticator.AAGUID
import java.security.interfaces.ECPublicKey

data class AttestationStatement(
    val x5c: List<ByteArray>,
    val receipt: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestationStatement

        if (x5c != other.x5c) return false
        if (!receipt.contentEquals(other.receipt)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = x5c.hashCode()
        result = 31 * result + receipt.contentHashCode()
        return result
    }
}

data class AppleAppAttestStatement(
    val fmt: String,
    val attStmt: AttestationStatement,
    val authData: ByteArray
) {
    companion object {
        const val APPLE_ATTESTATION_FORMAT_NAME = "apple-appattest"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AppleAppAttestStatement

        if (fmt != other.fmt) return false
        if (attStmt != other.attStmt) return false
        if (!authData.contentEquals(other.authData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = fmt.hashCode()
        result = 31 * result + attStmt.hashCode()
        result = 31 * result + authData.contentHashCode()
        return result
    }
}

enum class AppleAppAttestEnvironment(val identifier: String) {
    DEVELOPMENT("appattestdevelop"),
    PRODUCTION("appattest");

    companion object {
        const val AAGUID_LENGTH = 16
    }

    fun asAaguid(): AAGUID = AAGUID(
        ByteArray(AAGUID_LENGTH).apply {
            identifier.toByteArray().copyInto(this, 0)
        }
    )
}

data class AppleAppAttestValidationResponse(
    val publicKey: ECPublicKey,
    val receipt: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AppleAppAttestValidationResponse

        if (publicKey != other.publicKey) return false
        if (!receipt.contentEquals(other.receipt)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.hashCode()
        result = 31 * result + receipt.contentHashCode()
        return result
    }
}
