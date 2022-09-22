package ch.veehait.devicecheck.appattest.assertion

import java.security.interfaces.ECPublicKey

interface AssertionChallengeValidator {
    fun validate(
        assertionObj: Assertion,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        challenge: ByteArray
    ): Boolean
}
