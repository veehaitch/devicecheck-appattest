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
import java.time.Duration

/**
 * Factory class to create instances to validate attestations ([AttestationValidator]), assertions
 * ([AssertionValidator]), receipts ([ReceiptValidator]) and to request a new receipt ([ReceiptExchange]).
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

    private val defaultAppleDeviceCheckUrl: URI = when (appleAppAttestEnvironment) {
        AppleAppAttestEnvironment.DEVELOPMENT -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL
        AppleAppAttestEnvironment.PRODUCTION -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL
    }

    /**
     * Create an instance of an [AttestationValidator].
     *
     * @property trustAnchor The root certificate which serves as trust anchor for the attestation certificate chain.
     * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
     * @property receiptValidator A [ReceiptValidator] to validate the receipt contained in the attestation statement.
     * @see AttestationValidator
     */
    @JvmOverloads
    fun createAttestationValidator(
        trustAnchor: TrustAnchor = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR,
        clock: Clock = Clock.systemUTC(),
        receiptValidator: ReceiptValidator = createReceiptValidator(clock = clock),
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
     * @property trustAnchor The root certificate which serves as trust anchor for the receipt certificate chain.
     * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
     * @property maxAge The maximum validity period of a receipt. Defaults to
     *   [ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE] which reflects the value Apple recommends.
     * @see ReceiptValidator
     */
    @JvmOverloads
    fun createReceiptValidator(
        trustAnchor: TrustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
        clock: Clock = Clock.systemUTC(),
        maxAge: Duration = ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE,
    ): ReceiptValidator = ReceiptValidatorImpl(
        app = app,
        trustAnchor = trustAnchor,
        clock = clock,
        maxAge = maxAge,
    )

    /**
     * Create an instance of a [ReceiptExchange].
     *
     * @property appleJwsGenerator An [AppleJwsGenerator] instance to issue a signed JWT for authentication to Apple's
     *   App Attest server.
     * @property receiptValidator A [ReceiptValidator] to assert the validity of passed and returned receipts.
     * @property appleReceiptExchangeHttpClientAdapter An HTTP client adapter to execute the call to
     *   [appleDeviceCheckUrl] using [appleJwsGenerator] for authentication.
     * @property appleDeviceCheckUrl The endpoint to use for trading a receipt. Defaults to the server url given in
     *   Apple's documentation while taking [appleAppAttestEnvironment] into consideration.
     * @property sanityChecks Perform sanity checks on the passed receipt for calls to [ReceiptExchange.trade] and
     *   [ReceiptExchange.tradeAsync] to anticipate Apple's response. Defaults to true to prevent remote calls when
     *   possible.
     * @see ReceiptExchange
     */
    @JvmOverloads
    fun createReceiptExchange(
        appleJwsGenerator: AppleJwsGenerator,
        receiptValidator: ReceiptValidator = createReceiptValidator(),
        appleReceiptExchangeHttpClientAdapter: AppleReceiptExchangeHttpClientAdapter =
            SimpleAppleReceiptExchangeHttpClientAdapter(),
        appleDeviceCheckUrl: URI = defaultAppleDeviceCheckUrl,
        sanityChecks: Boolean = true,
    ): ReceiptExchange = ReceiptExchangeImpl(
        appleJwsGenerator = appleJwsGenerator,
        receiptValidator = receiptValidator,
        appleDeviceCheckUrl = appleDeviceCheckUrl,
        appleReceiptExchangeHttpClientAdapter = appleReceiptExchangeHttpClientAdapter,
        sanityChecks = sanityChecks,
    )
}
