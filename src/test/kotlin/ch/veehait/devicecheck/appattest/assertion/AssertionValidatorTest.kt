package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.readTextResource
import io.kotest.core.spec.style.StringSpec
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

class AssertionValidatorTest : StringSpec() {
    init {
        fun loadP256PublicKey(encoded: ByteArray): ECPublicKey {
            val factory = KeyFactory.getInstance("EC", BouncyCastleProvider())
            return factory.generatePublic(X509EncodedKeySpec(encoded)) as ECPublicKey
        }

        fun loadP256PublicKey(pem: String): ECPublicKey {
            val input = pem.toByteArray().inputStream()
            val pemParser = PEMParser(input.reader())
            val keyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject())

            return loadP256PublicKey(keyInfo.encoded)
        }

        "Validating an assertion works" {
            val assertion = javaClass.readTextResource("/iOS14-assertion-response-base64.cbor").fromBase64()

            val assertionValidator = AssertionValidatorImpl(
                "6MURL8TA57",
                "de.vincent-haupert.apple-appattest-poc",
            )

            val assertionChallengeValidator = object : AssertionChallengeValidator {
                override fun validate(
                    assertionObj: Assertion,
                    clientData: ByteArray,
                    attestationPublicKey: ECPublicKey,
                    challenge: ByteArray,
                ): Boolean {
                    return true
                }
            }

            assertionValidator.validate(
                assertion = assertion,
                clientData = "wurzelpfropf".toByteArray(),
                attestationPublicKey = loadP256PublicKey(
                    """
                    -----BEGIN PUBLIC KEY-----
                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXvYZVfyF46DnSS0+lythdJzwbK52L
                    hBg/hbRbGAluH2AUTB2wF6aVZFUwJ/U+nMWn1YJytGLStxD8/N0sdiiHA==
                    -----END PUBLIC KEY-----
                    """.trimIndent()
                ),
                lastCounter = 0L,
                challenge = ByteArray(0),
                assertionChallengeValidator = assertionChallengeValidator,
            )
        }
    }
}
