package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.assertion.AssertionChallengeValidator
import ch.veehait.devicecheck.appattest.assertion.AssertionValidator
import ch.veehait.devicecheck.appattest.assertion.AssertionValidatorImpl
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidatorImpl
import ch.veehait.devicecheck.appattest.receipt.AppleJwsGenerator
import ch.veehait.devicecheck.appattest.receipt.AppleReceiptHttpClientAdapter
import ch.veehait.devicecheck.appattest.receipt.ReceiptExchange
import ch.veehait.devicecheck.appattest.receipt.ReceiptExchangeImpl
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidatorImpl
import ch.veehait.devicecheck.appattest.receipt.SimpleAppleReceiptHttpClientAdapter
import java.net.URI
import java.security.cert.TrustAnchor
import java.time.Clock

class AppleAppAttest(
    private val app: App,
    private val appleAppAttestEnvironment: AppleAppAttestEnvironment,
) {
    fun createAttestationValidator(
        trustAnchor: TrustAnchor = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR,
        receiptValidator: ReceiptValidator = createReceiptValidator(trustAnchor),
        clock: Clock = Clock.systemUTC(),
    ): AttestationValidator = AttestationValidatorImpl(
        app = app,
        appleAppAttestEnvironment = appleAppAttestEnvironment,
        clock = clock,
        receiptValidator = receiptValidator,
        trustAnchor = trustAnchor,
    )

    fun createAssertionValidator(
        assertionChallengeValidator: AssertionChallengeValidator,
    ): AssertionValidator = AssertionValidatorImpl(
        app = app,
        assertionChallengeValidator = assertionChallengeValidator,
    )

    fun createReceiptValidator(
        trustAnchor: TrustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
        clock: Clock = Clock.systemUTC(),
    ): ReceiptValidator = ReceiptValidatorImpl(
        app = app,
        trustAnchor = trustAnchor,
        clock = clock,
    )

    fun createReceiptExchange(
        appleJwsGenerator: AppleJwsGenerator,
        receiptValidator: ReceiptValidator = createReceiptValidator(),
        appleDeviceCheckUrl: URI = ReceiptExchange.APPLE_DEVICE_CHECK_DEVELOPMENT_BASE_URL,
        appleReceiptHttpClientAdapter: AppleReceiptHttpClientAdapter = SimpleAppleReceiptHttpClientAdapter(),
    ): ReceiptExchange = ReceiptExchangeImpl(
        appleJwsGenerator = appleJwsGenerator,
        receiptValidator = receiptValidator,
        appleDeviceCheckUrl = appleDeviceCheckUrl,
        appleReceiptHttpClientAdapter = appleReceiptHttpClientAdapter,
    )
}
