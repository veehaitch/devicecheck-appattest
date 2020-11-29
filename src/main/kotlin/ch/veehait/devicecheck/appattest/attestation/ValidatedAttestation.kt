package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.receipt.Receipt
import java.security.cert.X509Certificate

/**
 * The validated attestation certificate and receipt contained in the Apple App Attest attestation object.
 *
 * @property certificate The attestation certificate.
 * @property receipt An initial receipt to obtain a fraud risk metric with Apple's server.
 */
data class ValidatedAttestation(
    val certificate: X509Certificate,
    val receipt: Receipt,
)
