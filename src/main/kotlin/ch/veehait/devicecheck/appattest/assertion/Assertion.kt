package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.common.AuthenticatorData

data class Assertion(
    val signature: ByteArray,
    val authenticatorData: AuthenticatorData,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Assertion

        if (!signature.contentEquals(other.signature)) return false
        if (authenticatorData != other.authenticatorData) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + authenticatorData.hashCode()
        return result
    }
}

internal data class AssertionEnvelope(
    val signature: ByteArray,
    val authenticatorData: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AssertionEnvelope

        if (!signature.contentEquals(other.signature)) return false
        if (!authenticatorData.contentEquals(other.authenticatorData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + authenticatorData.contentHashCode()
        return result
    }
}
