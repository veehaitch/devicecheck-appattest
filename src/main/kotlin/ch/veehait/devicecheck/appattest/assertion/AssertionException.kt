package ch.veehait.devicecheck.appattest.assertion

sealed class AssertionException(message: String, cause: Throwable?) : RuntimeException(message, cause) {
    class InvalidAuthenticatorData(message: String) : AssertionException(message, null)
    class InvalidSignature(cause: Throwable? = null) : AssertionException("The assertion's signature is invalid", cause)
    class InvalidChallenge(message: String, cause: Throwable? = null) : AssertionException(message, cause)
}
