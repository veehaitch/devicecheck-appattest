package ch.veehait.devicecheck.appattest.receipt

sealed class ReceiptException(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {
    class InvalidCertificateChain(msg: String, cause: Throwable? = null) : ReceiptException(msg, cause)
    class InvalidSignature(msg: String) : ReceiptException(msg)
    class InvalidPayload(msg: String) : ReceiptException(msg)
}

sealed class ReceiptExchangeException(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {
    class HttpError(message: String, cause: Throwable? = null) : ReceiptExchangeException(message, cause)
}
