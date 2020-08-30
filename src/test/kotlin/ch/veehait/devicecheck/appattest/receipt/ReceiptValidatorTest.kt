package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestStatement
import ch.veehait.devicecheck.appattest.fromBase64
import ch.veehait.devicecheck.appattest.readTextResource
import ch.veehait.devicecheck.appattest.readX509PublicKey
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.kotest.core.spec.style.StringSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class ReceiptValidatorTest : StringSpec() {
    init {
        val fixedClock = Clock.fixed(Instant.parse("2020-08-23T11:03:36.059Z"), ZoneOffset.UTC)

        "validation succeeds for valid receipt" {
            val cborObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()
            val attestationObjectBase64 = javaClass.readTextResource("/iOS14-attestation-response-base64.cbor")
            val attestStatement: AppleAppAttestStatement = cborObjectMapper.readValue(attestationObjectBase64.fromBase64())
            val receipt = attestStatement.attStmt.receipt

            val receiptValidator = ReceiptValidator(
                "6MURL8TA57",
                "de.vincent-haupert.apple-appattest-poc",
                clock = fixedClock
            )
            receiptValidator.validateReceipt(
                receipt,
                readX509PublicKey(
                    (
                        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXvYZVfyF46DnSS0+lythdJ" +
                            "zwbK52LhBg/hbRbGAluH2AUTB2wF6aVZFUwJ/U+nMWn1YJytGLStxD8/N0sdiiHA=="
                        ).fromBase64()
                )
            )
        }
    }
}
