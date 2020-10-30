package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.util.Extensions.sha256
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * Interface to validate the authenticity of an Apple App Attest assertion.
 *
 * @property app The connecting app.
 * @property assertionChallengeValidator An instance of [AssertionChallengeValidator] which validates the challenge
 *   included in the assertion. The implementation is specific to the [app] and the backend it connects to.
 */
interface AssertionValidator {
    val app: App
    val assertionChallengeValidator: AssertionChallengeValidator

    /**
     * Validate an assertion object.
     *
     * @param assertionObject attestation object created by calling
     *   `DCAppAttestService.generateAssertion(_:clientDataHash:completionHandler:)`
     * @param clientData The data the client asserted. Make sure to pass the raw data before hashing.
     * @param attestationPublicKey The attested public key stored for the client which sent the [assertionObject].
     * @param lastCounter The value of the counter which was validated last.
     * @param challenge The challenge the client included in [clientData] and which is validated
     *   using [assertionChallengeValidator].
     * @return A parsed and validated [Assertion].
     *
     * @throws AssertionException
     */
    fun validate(
        assertionObject: ByteArray,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        lastCounter: Long,
        challenge: ByteArray,
    ): Assertion

    /**
     * Validate an assertion object. Suspending version of [validate].
     *
     * @see [validate]
     */
    suspend fun validateAsync(
        assertionObject: ByteArray,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        lastCounter: Long,
        challenge: ByteArray,
    ): Assertion
}

internal class AssertionValidatorImpl(
    override val app: App,
    override val assertionChallengeValidator: AssertionChallengeValidator,
) : AssertionValidator {
    private val cborObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()
    private val signatureInstance = Signature.getInstance("SHA256withECDSA")

    private fun verifySignature(
        assertionEnvelope: AssertionEnvelope,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
    ) {
        // 1. Compute clientDataHash as the SHA256 hash of clientData.
        val clientDataHash = clientData.sha256()

        // 2. Concatenate authenticatorData and clientDataHash and apply a SHA256 hash over the result to form nonce.
        val nonce = assertionEnvelope.authenticatorData.plus(clientDataHash).sha256()

        // 3. Use the public key that you stored from the attestation object to verify
        //    that the assertion’s signature is valid for nonce.
        runCatching {
            signatureInstance.run {
                initVerify(attestationPublicKey)
                update(nonce)
                verify(assertionEnvelope.signature)
            }
        }.onFailure { cause ->
            throw AssertionException.InvalidSignature(cause)
        }.onSuccess { valid ->
            if (!valid) {
                throw AssertionException.InvalidSignature()
            }
        }
    }

    @Suppress("ThrowsCount")
    private fun verifyAuthenticatorData(
        authenticatorDataBlob: ByteArray,
        lastCounter: Long,
    ): Assertion.AssertionAuthenticatorData {
        // XXX: We cannot use [Utils.parseAuthenticatorData] here as Apple sets the "Extension Data" (ED) flag
        //      although it does not contain any. Using an own structure which ignores the flags altogether until
        //      Apple fixes this.
        val authenticatorData = runCatching { Assertion.AssertionAuthenticatorData.parse(authenticatorDataBlob) }
            .getOrElse {
                throw AssertionException.InvalidAuthenticatorData("Could not parse assertion authenticatorData")
            }
        // 4. Compute the SHA256 hash of the client’s App ID,
        //    and verify that it matches the RP ID in the authenticator data.
        val expectedRpId = app.appIdentifier.toByteArray().sha256()
        if (!expectedRpId.contentEquals(authenticatorData.rpIdHash)) {
            throw AssertionException.InvalidAuthenticatorData("App ID hash does not match RP ID hash")
        }

        // 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion,
        //    or greater than 0 on the first assertion.
        if (authenticatorData.signCount <= lastCounter) {
            throw AssertionException.InvalidAuthenticatorData(
                "Assertion counter is not greater than the counter saved counter"
            )
        }

        return authenticatorData
    }

    private fun verifyChallenge(
        challenge: ByteArray,
        assertionObj: Assertion,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
    ) {
        // 6. Verify that the challenge embedded in the client data matches the earlier challenge to the client.
        val challengeIsValid = assertionChallengeValidator.validate(
            assertionObj = assertionObj,
            clientData = clientData,
            attestationPublicKey = attestationPublicKey,
            challenge = challenge,
        )

        if (!challengeIsValid) {
            throw AssertionException.InvalidChallenge("The given challenge is invalid")
        }
    }

    override suspend fun validateAsync(
        assertionObject: ByteArray,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        lastCounter: Long,
        challenge: ByteArray,
    ): Assertion = coroutineScope {
        val assertionEnvelope: AssertionEnvelope = cborObjectMapper.readValue(assertionObject)

        launch { verifySignature(assertionEnvelope, clientData, attestationPublicKey) }

        val authenticatorData = async {
            verifyAuthenticatorData(assertionEnvelope.authenticatorData, lastCounter)
        }

        val assertion = Assertion(assertionEnvelope.signature, authenticatorData.await())

        launch { verifyChallenge(challenge, assertion, clientData, attestationPublicKey) }

        assertion
    }

    override fun validate(
        assertionObject: ByteArray,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        lastCounter: Long,
        challenge: ByteArray,
    ): Assertion = runBlocking {
        validateAsync(assertionObject, clientData, attestationPublicKey, lastCounter, challenge)
    }
}
