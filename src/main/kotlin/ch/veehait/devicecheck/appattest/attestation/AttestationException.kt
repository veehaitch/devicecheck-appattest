package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.Extensions.toBase64

sealed class AttestationException(message: String, cause: Throwable?) : RuntimeException(message, cause) {
    class InvalidFormatException(message: String, cause: Throwable? = null) : AttestationException(message, cause)
    class InvalidCertificateChain(message: String, cause: Throwable? = null) : AttestationException(message, cause)
    class InvalidNonce(cause: Throwable? = null) : AttestationException("The attestation's nonce is invalid", cause)
    class InvalidPublicKey(keyId: ByteArray) :
        AttestationException("Expected key identifier '${keyId.toBase64()}'", null)

    class InvalidReceipt(cause: Throwable) : AttestationException(
        "The attestation statement receipt did not pass validation",
        cause
    )

    class InvalidAuthenticatorData(message: String) : AttestationException(message, null)
}
