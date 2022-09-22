package ch.veehait.devicecheck.appattest.attestation

import javax.annotation.processing.Generated

internal data class AttestationObject(
    val fmt: String,
    val attStmt: AttestationStatement,
    val authData: ByteArray
) {
    data class AttestationStatement(
        val x5c: List<ByteArray>,
        val receipt: ByteArray
    ) {
        @Generated
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AttestationStatement

            if (x5c != other.x5c) return false
            if (!receipt.contentEquals(other.receipt)) return false

            return true
        }

        @Generated
        override fun hashCode(): Int {
            var result = x5c.hashCode()
            result = 31 * result + receipt.contentHashCode()
            return result
        }
    }
    companion object {
        const val APPLE_APP_ATTEST_ATTESTATION_STATEMENT_FORMAT_IDENTIFIER = "apple-appattest"
    }

    @Generated
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestationObject

        if (fmt != other.fmt) return false
        if (attStmt != other.attStmt) return false
        if (!authData.contentEquals(other.authData)) return false

        return true
    }

    @Generated
    override fun hashCode(): Int {
        var result = fmt.hashCode()
        result = 31 * result + attStmt.hashCode()
        result = 31 * result + authData.contentHashCode()
        return result
    }
}
