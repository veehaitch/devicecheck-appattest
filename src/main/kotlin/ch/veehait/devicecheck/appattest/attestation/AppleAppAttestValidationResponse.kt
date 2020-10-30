package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.receipt.Receipt
import java.security.interfaces.ECPublicKey

/**
 * The validated public key and receipt contained in the Apple App Attest attestation object.
 *
 * @property publicKey The attested P-256 public key.
 * @property receipt An initial receipt to obtain a fraud risk metric with Apple's server.
 */
data class AppleAppAttestValidationResponse(
    val publicKey: ECPublicKey,
    val receipt: Receipt
)
