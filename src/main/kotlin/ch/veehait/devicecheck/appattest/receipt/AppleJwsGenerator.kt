package ch.veehait.devicecheck.appattest.receipt

import java.security.PrivateKey

/**
 * Interface to generate a signed JWT to use for authentication with Apple's servers.
 *
 * @property teamIdentifier The 10-digit identifier of the team which signs your app, as denoted on
 *   https://developer.apple.com/account. Also known as app identifier prefix (without the trailing dot).
 * @property keyIdentifier A string that identifies the key used to generate the signature. The key must have been
 *   created with the DeviceCheck service enabled.
 * @property privateKey The private key used to create the JWT signature.
 */
interface AppleJwsGenerator {
    val teamIdentifier: String
    val keyIdentifier: String
    val privateKey: PrivateKey

    /**
     * Generate a JWT signed with the [privateKey] with [keyIdentifier] and issuer [teamIdentifier].
     *
     * @return A token suitable for HTTP bearer authorization.
     */
    fun issueToken(): String
}
