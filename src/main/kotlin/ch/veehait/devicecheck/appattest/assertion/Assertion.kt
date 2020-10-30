package ch.veehait.devicecheck.appattest.assertion

import java.nio.ByteBuffer

data class Assertion(
    val signature: ByteArray,
    val authenticatorData: AssertionAuthenticatorData,
) {
    data class AssertionAuthenticatorData(
        val rpIdHash: ByteArray,
        val signCount: Long,
    ) {
        companion object {
            @Suppress("MagicNumber")
            fun parse(data: ByteArray) = AssertionAuthenticatorData(
                rpIdHash = data.sliceArray(0 until 32),
                signCount = data.sliceArray(33 until 37)
                    .let(ByteBuffer::wrap)
                    .int
                    .let(Integer::toUnsignedLong)
            )
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AssertionAuthenticatorData

            if (!rpIdHash.contentEquals(other.rpIdHash)) return false
            if (signCount != other.signCount) return false

            return true
        }

        override fun hashCode(): Int {
            var result = rpIdHash.contentHashCode()
            result = 31 * result + signCount.hashCode()
            return result
        }
    }

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
