package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.assertion.AssertionChallengeValidator
import ch.veehait.devicecheck.appattest.assertion.AssertionValidator
import ch.veehait.devicecheck.appattest.assertion.AssertionValidatorImpl
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidatorImpl
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.receipt.AppleJwsGenerator
import ch.veehait.devicecheck.appattest.receipt.AppleReceiptExchangeHttpClientAdapter
import ch.veehait.devicecheck.appattest.receipt.ReceiptExchange
import ch.veehait.devicecheck.appattest.receipt.ReceiptExchangeImpl
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidatorImpl
import ch.veehait.devicecheck.appattest.receipt.SimpleAppleReceiptExchangeHttpClientAdapter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.net.URI
import java.security.Security
import java.security.cert.TrustAnchor
import java.time.Clock

/**
 * Factory class to create instances to validate attestations ([AttestationValidator]), assertions
 * ([AssertionValidator]), receipt ([ReceiptValidator]) and to request a new receipt ([ReceiptExchange]).
 *
 * @property app The connecting app.
 * @property appleAppAttestEnvironment The Apple App Attest environment; either "appattestdevelop" or "appattest".
 */
class AppleAppAttest(
    val app: App,
    val appleAppAttestEnvironment: AppleAppAttestEnvironment,
) {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * Create an instance of an [AttestationValidator].
     *
     * @property trustAnchor The root of the App Attest certificate chain.
     * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
     * @property receiptValidator A [ReceiptValidator] to validate the receipt contained in the attestation statement.
     * @see AttestationValidator
     */
    fun createAttestationValidator(
        trustAnchor: TrustAnchor = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR,
        clock: Clock = Clock.systemUTC(),
        receiptValidator: ReceiptValidator = createReceiptValidator(trustAnchor, clock),
    ): AttestationValidator = AttestationValidatorImpl(
        app = app,
        appleAppAttestEnvironment = appleAppAttestEnvironment,
        clock = clock,
        receiptValidator = receiptValidator,
        trustAnchor = trustAnchor,
    )

    /**
     * Create an instance of an [AssertionValidator].
     *
     * @property assertionChallengeValidator An instance of [AssertionChallengeValidator] which validates the challenge
     *   included in the assertion. The implementation is specific to the [app] and the backend it connects to.
     * @see AssertionValidator
     */
    fun createAssertionValidator(
        assertionChallengeValidator: AssertionChallengeValidator,
    ): AssertionValidator = AssertionValidatorImpl(
        app = app,
        assertionChallengeValidator = assertionChallengeValidator,
    )

    /**
     * Create an instance of a [ReceiptValidator].
     *
     * @property trustAnchor The root of the receipt certificate chain.
     * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
     * @see ReceiptValidator
     */
    fun createReceiptValidator(
        trustAnchor: TrustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
        clock: Clock = Clock.systemUTC(),
    ): ReceiptValidator = ReceiptValidatorImpl(
        app = app,
        trustAnchor = trustAnchor,
        clock = clock,
    )

    /**
     * Create an instance of a [ReceiptExchange].
     *
     * @property appleJwsGenerator An [AppleJwsGenerator] instance to issue a signed JWT for authentication to Apple's
     *   App Attest server.
     * @property receiptValidator A [ReceiptValidator] to assert the validity of passed and returned receipts.
     * @property appleDeviceCheckUrl The endpoint to use for trading a receipt.
     * @property appleReceiptExchangeHttpClientAdapter An HTTP client adapter to execute the call to
     *   [appleDeviceCheckUrl] using [appleJwsGenerator] for authentication.
     * @see ReceiptExchange
     */
    fun createReceiptExchange(
        appleJwsGenerator: AppleJwsGenerator,
        receiptValidator: ReceiptValidator = createReceiptValidator(),
        appleDeviceCheckUrl: URI = ReceiptExchange.APPLE_DEVICE_CHECK_DEVELOPMENT_BASE_URL,
        appleReceiptExchangeHttpClientAdapter: AppleReceiptExchangeHttpClientAdapter =
            SimpleAppleReceiptExchangeHttpClientAdapter(),
    ): ReceiptExchange = ReceiptExchangeImpl(
        appleJwsGenerator = appleJwsGenerator,
        receiptValidator = receiptValidator,
        appleDeviceCheckUrl = appleDeviceCheckUrl,
        appleReceiptExchangeHttpClientAdapter = appleReceiptExchangeHttpClientAdapter,
    )
}
