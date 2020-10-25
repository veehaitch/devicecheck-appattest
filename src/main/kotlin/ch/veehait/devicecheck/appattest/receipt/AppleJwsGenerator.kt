package ch.veehait.devicecheck.appattest.receipt

import java.security.PrivateKey

interface AppleJwsGenerator {
    val appleTeamIdentifier: String
    val keyIdentifier: String
    val privateKey: PrivateKey

    /**
     * Generate a JWT signed with the [privateKey] with [keyIdentifier] and issuer [appleTeamIdentifier]
     *
     * @return A token suitable for HTTP bearer authorization
     */
    fun issueToken(): String
}
