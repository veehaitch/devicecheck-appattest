package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.TestExtensions.encode
import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.TestUtils.cborObjectMapper
import ch.veehait.devicecheck.appattest.TestUtils.jsonObjectMapper
import ch.veehait.devicecheck.appattest.TestUtils.loadValidAttestationSample
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.receipt.Receipt
import ch.veehait.devicecheck.appattest.util.Extensions.createAppleKeyId
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.sha256
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import ch.veehait.devicecheck.appattest.util.Utils
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import nl.jqno.equalsverifier.EqualsVerifier
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.TrustAnchor
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class AttestationValidatorTest : StringSpec() {
    init {
        Security.addProvider(BouncyCastleProvider())

        "AttestationStatement: equals/hashCode" {
            EqualsVerifier.forClass(AttestationObject.AttestationStatement::class.java).verify()
        }

        "AppleAppAttestStatement: equals/hashCode" {
            EqualsVerifier.forClass(AttestationObject::class.java).verify()
        }

        "Throws InvalidFormatException for wrong attestation format" {
            // Test setup
            val (attestationSample, app, clock) = loadValidAttestationSample()
            val attestationValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAttestationValidator(
                clock = clock
            )

            // Actual test
            shouldThrow<AttestationException.InvalidFormatException> {
                with(attestationSample) {
                    val attestationStatement = cborObjectMapper.readValue(attestation, AttestationObject::class.java)
                    val attestationStatementWrong = attestationStatement.copy(fmt = "wurzelpfropf")
                    val attestationWrong = cborObjectMapper.writeValueAsBytes(attestationStatementWrong)
                    attestationValidator.validate(attestationWrong, keyId.toBase64(), clientData)
                }
            }
        }

        "Throws InvalidAuthenticatorData for wrong keyId" {
            val (attestationSample, app, clock) = loadValidAttestationSample()
            val attestationValidator = AppleAppAttest(
                app = app.copy(teamIdentifier = "A".repeat(10)),
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAttestationValidator(
                clock = clock
            )

            val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                with(attestationSample) {
                    attestationValidator.validate(attestation, keyId.toBase64(), clientData)
                }
            }
            exception.message.shouldBe("App ID does not match RP ID hash")
        }

        "Throws InvalidPublicKey for wrong appId" {
            // Test setup
            val (attestationSample, app, clock) = loadValidAttestationSample()
            val attestationValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAttestationValidator(
                clock = clock
            )

            // Actual test
            shouldThrow<AttestationException.InvalidPublicKey> {
                with(attestationSample) {
                    val wrongKeyId = "fporfplezruw".toByteArray().sha256().toBase64()
                    attestationValidator.validate(attestation, wrongKeyId, clientData)
                }
            }
        }

        "Throws InvalidNonce for wrong challenge" {
            // Test setup
            val (attestationSample, app, clock) = loadValidAttestationSample()
            val attestationValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAttestationValidator(
                clock = clock
            )

            // Actual test
            shouldThrow<AttestationException.InvalidNonce> {
                with(attestationSample) {
                    val wrongChallenge = "fporfplezruw".toByteArray()
                    attestationValidator.validate(attestation, keyId.toBase64(), wrongChallenge)
                }
            }
        }

        "Throws InvalidCertificateChain for wrong trust anchor" {
            val wrongCa =
                """
                -----BEGIN CERTIFICATE-----
                MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
                BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy
                ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
                Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
                tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
                C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
                oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
                sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
                igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
                aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
                AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD
                VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO
                BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk
                Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD
                ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB
                Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m
                qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY
                DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm
                QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u
                JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD
                CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy
                ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD
                qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic
                MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1
                wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk
                -----END CERTIFICATE-----
                """.trimIndent()
            val wrongTrustAnchor = TrustAnchor(Utils.readPemX509Certificate(wrongCa), null)

            val (attestationSample, app, clock) = loadValidAttestationSample()
            val attestationValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAttestationValidator(
                clock = clock,
                trustAnchor = wrongTrustAnchor
            )

            shouldThrow<AttestationException.InvalidCertificateChain> {
                with(attestationSample) {
                    attestationValidator.validate(attestation, keyId.toBase64(), clientData)
                }
            }
        }

        "validation works for valid attestation object" {
            val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
            val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)

            val app = App(attestationSample.teamIdentifier, attestationSample.bundleIdentifier)
            val clock = Clock.fixed(attestationSample.timestamp.plusSeconds(5), ZoneOffset.UTC)
            val appleAppAttest = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            )
            val attestationValidator = appleAppAttest.createAttestationValidator(
                clock = clock,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = clock
                )
            )

            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            with(attestationResponse.receipt.payload) {
                appId.value shouldBe app.appIdentifier
                attestationCertificate.value.publicKey shouldBe attestationResponse.publicKey
                clientHash.value shouldBe "i+ZcylFa0JfJU5Z9GNY12G3XihQu09B3UmvtEca+xns=".fromBase64()
                creationTime.value shouldBe Instant.parse("2020-11-21T22:13:02.796Z")
                environment?.value shouldBe "sandbox"
                expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                notBefore.shouldBeNull()
                riskMetric.shouldBeNull()
                token.value shouldBe "7URCQP4mKgM9qW9M/zxuPweeyX0tvFfN5xTY4u9JYLPlTTfmL126irzJn0l+i4R7gloRfkoNiNixMAqUwW5jIQ=="
                type.value shouldBe Receipt.Type.ATTEST
            }
        }

        "validation works for valid fake attestation object".config(enabled = true) {
            val credCertKeyPair = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).apply {
                initialize(ECGenParameterSpec("prime256v1"))
            }.generateKeyPair()

            val (attestationSampleOriginal, app, clock) = loadValidAttestationSample()
            val appleAppAttest = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            )
            val attestationValidatorOriginal = appleAppAttest.createAttestationValidator(
                clock = clock,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = clock
                )
            )
            val attestationResponse = attestationValidatorOriginal.validate(
                attestationObject = attestationSampleOriginal.attestation,
                keyIdBase64 = attestationSampleOriginal.keyId.toBase64(),
                serverChallenge = attestationSampleOriginal.clientData
            )

            val attestationObject: AttestationObject = cborObjectMapper.readValue(attestationSampleOriginal.attestation)

            val authData: AuthenticatorData = AuthenticatorData.parse(
                attestationObject.authData,
                cborObjectMapper.readerForMapOf(Any::class.java)
            )

            val authDataFake = authData.copy(
                attestedCredentialData = authData.attestedCredentialData?.copy(
                    credentialId = credCertKeyPair.public.createAppleKeyId()
                )
            ).encode()

            val nonceFake = authDataFake.plus(attestationSampleOriginal.clientData.sha256()).sha256()

            val attCertChain = CertUtils.createCustomAttestationCertificate(
                x5c = attestationObject.attStmt.x5c,
                credCertKeyPair = credCertKeyPair,
                mutatorCredCert = { builder ->
                    val fakeNonceEncoded = DLSequence(
                        DLTaggedObject(true, 1, DEROctetString(nonceFake))
                    ).encoded
                    builder.replaceExtension(
                        ASN1ObjectIdentifier(AttestationValidator.APPLE_CRED_CERT_EXTENSION_OID),
                        false,
                        fakeNonceEncoded
                    )
                }
            )

            val resignedReceiptResponse = CertUtils.resignReceipt(
                receipt = attestationResponse.receipt,
                payloadMutator = {
                    it.copy(
                        attestationCertificate = Receipt.ReceiptAttribute.X509Certificate(
                            it.attestationCertificate.sequence.copy(
                                value = attCertChain.credCert.encoded
                            )
                        )
                    )
                },
            )

            val attestationObjectFake = attestationObject.copy(
                attStmt = attestationObject.attStmt.copy(
                    x5c = listOf(attCertChain.credCert.encoded, attCertChain.intermediateCa.encoded),
                    receipt = resignedReceiptResponse.receipt.p7,
                ),
                authData = authDataFake,
            )

            // ----------

            val attestationSample = attestationSampleOriginal.copy(
                attestation = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                keyId = attCertChain.credCert.createAppleKeyId(),
            )

            val attestationValidator = appleAppAttest.createAttestationValidator(
                clock = clock,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = clock,
                    trustAnchor = resignedReceiptResponse.trustAnchor,
                ),
                trustAnchor = TrustAnchor(attCertChain.rootCa, null)
            )

            attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData,
            )
        }
    }
}
