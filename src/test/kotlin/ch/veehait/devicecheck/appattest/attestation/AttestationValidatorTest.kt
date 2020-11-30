package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.TestExtensions.encode
import ch.veehait.devicecheck.appattest.TestExtensions.fixedUtcClock
import ch.veehait.devicecheck.appattest.TestUtils.cborObjectMapper
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.common.AuthenticatorDataFlag
import ch.veehait.devicecheck.appattest.receipt.Receipt
import ch.veehait.devicecheck.appattest.receipt.ReceiptException
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import ch.veehait.devicecheck.appattest.util.Extensions.createAppleKeyId
import ch.veehait.devicecheck.appattest.util.Extensions.sha256
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.throwable.shouldHaveCauseOfType
import io.kotest.matchers.throwable.shouldHaveMessage
import nl.jqno.equalsverifier.EqualsVerifier
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.cert.TrustAnchor
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

class AttestationValidatorTest : FreeSpec() {

    private fun AttestationSample.defaultValidator(): AttestationValidator {
        val appleAppAttest = this.defaultAppleAppAttest()
        return appleAppAttest.createAttestationValidator(
            clock = timestamp.fixedUtcClock(),
            receiptValidator = appleAppAttest.createReceiptValidator(
                clock = timestamp.fixedUtcClock(),
            )
        )
    }

    init {
        Security.addProvider(BouncyCastleProvider())

        "equals/hashCode" - {
            "AttestationObject.AttestationStatement" {
                EqualsVerifier.forClass(AttestationObject.AttestationStatement::class.java).verify()
            }

            "AttestationObject: equals/hashCode" {
                EqualsVerifier.forClass(AttestationObject::class.java).verify()
            }
        }

        "Accepts valid attestation samples" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidator = sample.defaultValidator()

                    val response = shouldNotThrowAny {
                        attestationValidator.validate(
                            attestationObject = sample.attestation,
                            keyIdBase64 = sample.keyId.toBase64(),
                            serverChallenge = sample.clientData
                        )
                    }
                    response.certificate.publicKey shouldBe sample.publicKey
                    response.iOSVersion shouldBe sample.iOSVersion
                }
            }
        }

        "Accepts valid fake attestation samples" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {

                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = credCertKeyPair.public.createAppleKeyId()
                        )
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    attestationValidator.validate(
                        attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                        keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                        serverChallenge = sample.clientData,
                    )
                }
            }
        }

        "Accepts valid fake attestation samples with missing iOS version extension" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = credCertKeyPair.public.createAppleKeyId()
                        )
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
                                false,
                                fakeNonceEncoded
                            )
                            // Validation should still succeed even if the iOS version cannot be parsed
                            builder.removeExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.OS_VERSION_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val result = attestationValidator.validate(
                        attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                        keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                        serverChallenge = sample.clientData,
                    )
                    result.iOSVersion.shouldBeNull()
                }
            }
        }

        "Throw InvalidReceipt for invalid receipt" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = object : ReceiptValidator {
                            override val app: App = appleAppAttest.app
                            override val trustAnchor: TrustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR
                            override val maxAge: Duration = ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE
                            override val clock: Clock = sample.timestamp.fixedUtcClock()

                            override suspend fun validateReceiptAsync(receiptP7: ByteArray, publicKey: ECPublicKey, notAfter: Instant): Receipt {
                                throw ReceiptException.InvalidPayload("Always rejected")
                            }

                            override fun validateReceipt(receiptP7: ByteArray, publicKey: ECPublicKey, notAfter: Instant): Receipt {
                                throw ReceiptException.InvalidPayload("Always rejected")
                            }
                        }
                    )

                    shouldThrow<AttestationException.InvalidReceipt> {
                        attestationValidator.validateAsync(
                            attestationObject = sample.attestation,
                            keyIdBase64 = sample.keyId.toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                }
            }
        }

        "Throws InvalidFormatException for wrong attestation format" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidator = sample.defaultValidator()

                    shouldThrow<AttestationException.InvalidFormatException> {
                        with(sample) {
                            val attestationStatement = cborObjectMapper.readValue(attestation, AttestationObject::class.java)
                            val attestationStatementWrong = attestationStatement.copy(fmt = "wurzelpfropf")
                            val attestationWrongFormat = cborObjectMapper.writeValueAsBytes(attestationStatementWrong)
                            attestationValidator.validate(
                                attestationObject = attestationWrongFormat,
                                keyIdBase64 = sample.keyId.toBase64(),
                                serverChallenge = sample.clientData,
                            )
                        }
                    }
                }
            }
        }

        "Throws InvalidAuthenticatorData for wrong appId" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidator = AppleAppAttest(
                        app = App("WURZELPFRO", "PF"),
                        appleAppAttestEnvironment = sample.environment,
                    ).createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                    )

                    val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                        attestationValidator.validate(
                            attestationObject = sample.attestation,
                            keyIdBase64 = sample.keyId.toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.message.shouldBe("App ID does not match RP ID hash")
                }
            }
        }

        "Throws InvalidPublicKey for wrong keyId" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidator = sample.defaultValidator()

                    shouldThrow<AttestationException.InvalidPublicKey> {
                        val wrongKeyId = "fporfplezruw".toByteArray().sha256().toBase64()
                        attestationValidator.validate(
                            attestationObject = sample.attestation,
                            keyIdBase64 = wrongKeyId,
                            serverChallenge = sample.clientData,
                        )
                    }
                }
            }
        }

        "Throws InvalidNonce for wrong challenge" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidator = sample.defaultValidator()

                    shouldThrow<AttestationException.InvalidNonce> {
                        val wrongChallenge = "fporfplezruw".toByteArray()
                        attestationValidator.validate(
                            attestationObject = sample.attestation,
                            keyIdBase64 = sample.keyId.toBase64(),
                            serverChallenge = wrongChallenge,
                        )
                    }
                }
            }
        }

        "Throws InvalidNonce for malformatted challenge" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = credCertKeyPair.public.createAppleKeyId(),
                        )
                    ).encode()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            builder.removeExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val exception = shouldThrow<AttestationException.InvalidNonce> {
                        attestationValidator.validate(
                            attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                            keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.cause!!.shouldHaveCauseOfType<NullPointerException>()
                }
            }
        }

        "Throws InvalidAuthenticatorData for missing attested credentials" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {

                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    // Omit attestedCredentialData for this test
                    val authDataFake = authData.copy(
                        attestedCredentialData = null,
                        flags = authData.flags.filterNot { it == AuthenticatorDataFlag.AT }
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                        attestationValidator.validate(
                            attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                            keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.shouldHaveMessage("Does not contain attested credentials")
                }
            }
        }

        "Throws InvalidAuthenticatorData for non-zero counter" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {

                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = credCertKeyPair.public.createAppleKeyId(),
                        ),
                        signCount = 1337L,
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                        attestationValidator.validate(
                            attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                            keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.shouldHaveMessage("Counter is not zero")
                }
            }
        }

        "Throws InvalidAuthenticatorData for invalid AAGUID" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = credCertKeyPair.public.createAppleKeyId(),
                            aaguid = UUID.randomUUID(),
                        ),
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                        attestationValidator.validate(
                            attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                            keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.shouldHaveMessage(
                        "AAGUID does match neither ${AppleAppAttestEnvironment.DEVELOPMENT} " +
                            "nor ${AppleAppAttestEnvironment.PRODUCTION}"
                    )
                }
            }
        }

        "Throws InvalidAuthenticatorData for wrong credentials ID" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val attestationValidatorOriginal = sample.defaultValidator()
                    val attestationResponse = attestationValidatorOriginal.validate(
                        attestationObject = sample.attestation,
                        keyIdBase64 = sample.keyId.toBase64(),
                        serverChallenge = sample.clientData
                    )

                    val attestationObject: AttestationObject = cborObjectMapper.readValue(sample.attestation)
                    val authData: AuthenticatorData = AuthenticatorData.parse(
                        attestationObject.authData,
                        cborObjectMapper.readerForMapOf(Any::class.java)
                    )

                    val credCertKeyPair = CertUtils.generateP256KeyPair()

                    val authDataFake = authData.copy(
                        attestedCredentialData = authData.attestedCredentialData?.copy(
                            credentialId = CertUtils.generateP256KeyPair().public.createAppleKeyId(),
                        ),
                    ).encode()
                    val nonceFake = authDataFake.plus(sample.clientData.sha256()).sha256()

                    val attCertChain = CertUtils.createCustomAttestationCertificate(
                        x5c = attestationObject.attStmt.x5c,
                        credCertKeyPair = credCertKeyPair,
                        mutatorCredCert = { builder ->
                            val fakeNonceEncoded = DLSequence(
                                DLTaggedObject(true, 1, DEROctetString(nonceFake))
                            ).encoded
                            builder.replaceExtension(
                                ASN1ObjectIdentifier(AttestationValidator.AppleCertificateExtensions.NONCE_OID),
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

                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                            trustAnchor = resignedReceiptResponse.trustAnchor,
                        ),
                        trustAnchor = TrustAnchor(attCertChain.rootCa, null)
                    )

                    val exception = shouldThrow<AttestationException.InvalidAuthenticatorData> {
                        attestationValidator.validate(
                            attestationObject = cborObjectMapper.writeValueAsBytes(attestationObjectFake),
                            keyIdBase64 = attCertChain.credCert.createAppleKeyId().toBase64(),
                            serverChallenge = sample.clientData,
                        )
                    }
                    exception.shouldHaveMessage("Credentials ID is not equal to Key ID")
                }
            }
        }

        "Throws InvalidCertificateChain for wrong trust anchor" - {
            AttestationSample.all.forEach { sample ->
                "${sample.id}" {
                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val attestationValidator = appleAppAttest.createAttestationValidator(
                        clock = sample.timestamp.fixedUtcClock(),
                        receiptValidator = appleAppAttest.createReceiptValidator(
                            clock = sample.timestamp.fixedUtcClock(),
                        ),
                        trustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
                    )

                    shouldThrow<AttestationException.InvalidCertificateChain> {
                        attestationValidator.validate(sample.attestation, sample.keyId.toBase64(), sample.clientData)
                    }
                }
            }
        }
    }
}
