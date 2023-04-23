package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.receipt.Receipt
import java.security.cert.X509Certificate

/**
 * The validated attestation certificate and receipt contained in the Apple App Attest attestation object.
 *
 * @property certificate The attestation certificate.
 * @property receipt An initial receipt to obtain a fraud risk metric with Apple's server.
 * @property iOSVersion The iOS version of the device of the attested app. Please note: this property is backed by a
 *   X.509 extension value of the attestation [certificate] which is not officially supported / lacks documentation.
 */
data class ValidatedAttestation(
    val certificate: X509Certificate,
    val receipt: Receipt,
    val iOSVersion: String?,
)
