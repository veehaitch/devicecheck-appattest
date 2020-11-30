package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import java.net.HttpURLConnection
import java.net.URI
import java.security.interfaces.ECPublicKey
import java.time.Instant

/**
 * Interface to perform a remote call to an Apple server to exchange an existing receipt for a new one.
 *
 * @property appleJwsGenerator An [AppleJwsGenerator] instance to issue a signed JWT for authentication to Apple's
 *   App Attest server.
 * @property receiptValidator A [ReceiptValidator] to assert the validity of passed and returned receipts.
 * @property appleDeviceCheckUrl The endpoint to use for trading a receipt.
 * @property appleReceiptExchangeHttpClientAdapter An HTTP client adapter to execute the call to [appleDeviceCheckUrl]
 *   using [appleJwsGenerator] for authentication.
 * @property sanityChecks Perform sanity checks on the passed receipt for calls to [trade]/[tradeAsync] to anticipate
 *   Apple's response.
 */
interface ReceiptExchange {
    val appleJwsGenerator: AppleJwsGenerator
    val receiptValidator: ReceiptValidator
    val appleReceiptExchangeHttpClientAdapter: AppleReceiptExchangeHttpClientAdapter
    val appleDeviceCheckUrl: URI
    val sanityChecks: Boolean

    companion object {
        @JvmStatic
        /** The Apple App Attest receipt endpoint for production use */
        val APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL: URI = URI.create(
            "https://data.appattest.apple.com/v1/attestationData"
        )

        @JvmStatic
        /** The Apple App Attest receipt endpoint for development use */
        val APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL: URI = URI.create(
            "https://data-development.appattest.apple.com/v1/attestationData"
        )
    }

    /**
     * Exchange a [receiptP7] for a new one. Suspending version of [trade].
     *
     * @see trade
     */
    suspend fun tradeAsync(
        receiptP7: ByteArray,
        attestationPublicKey: ECPublicKey,
        sanityChecks: Boolean = this.sanityChecks,
    ): Receipt = coroutineScope {
        // Validate the receipt before sending it to Apple. We cannot validate the creation time as we do not know when
        // it should have been issued at latest. Therefore, we use an epoch instant which de facto skips this check. As
        // we also validate the new receipt on return, this should be acceptable.
        val receipt = receiptValidator.validateReceiptAsync(receiptP7, attestationPublicKey, Instant.EPOCH)

        if (sanityChecks) {
            val now = receiptValidator.clock.instant()
            // If the passed receipt's "not before" date has not yet passed, Apple would respond with the same receipt.
            if (receipt.payload.notBefore != null && now < receipt.payload.notBefore.value) {
                return@coroutineScope receipt
            }

            // If the passed receipt's "not after" date has already passed, Apple would not respond with a new receipt.
            val expirationDate = receipt.payload.expirationTime.value
            if (now >= expirationDate) {
                throw ReceiptExchangeException.ReceiptExpired(expirationDate)
            }
        }

        val authorizationHeader = async { mapOf("Authorization" to appleJwsGenerator.issueToken()) }

        val response = appleReceiptExchangeHttpClientAdapter.post(
            appleDeviceCheckUrl,
            authorizationHeader.await(),
            receipt.p7.toBase64().toByteArray(),
        )

        when (response.statusCode) {
            HttpURLConnection.HTTP_OK -> receiptValidator.validateReceiptAsync(
                receiptP7 = response.body.fromBase64(),
                publicKey = attestationPublicKey
            )
            // Apple docs: "You made the request before the previous receipt’s “Not Before” date."
            HttpURLConnection.HTTP_NOT_MODIFIED -> receipt
            else -> {
                handleErrorResponse(response)
                throw ReceiptExchangeException.HttpError("Caught an error in Apple's response: $response")
            }
        }
    }

    /**
     * Exchange a [receiptP7] for a new one.
     *
     * Also verifies the validity of the passed [receiptP7] and the returned receipt.
     *
     * @param receiptP7 A PKCS#7 receipt obtained in a previous remote call to Apple or from an attestation statement
     * @param attestationPublicKey The public key of the initial attestation statement
     * @param sanityChecks Allows overriding the value of [ReceiptExchange.sanityChecks] for this call.
     * @return A new receipt superseding the old one. The returned receipt may be equal to the parsed [receiptP7] if
     *   [Receipt.Payload.notBefore] has not yet passed.
     */
    fun trade(
        receiptP7: ByteArray,
        attestationPublicKey: ECPublicKey,
        sanityChecks: Boolean = this.sanityChecks,
    ): Receipt = runBlocking {
        tradeAsync(receiptP7, attestationPublicKey)
    }

    /**
     * Handle any response with a status code not equal to 200 (OK).
     *
     * @param response The response from the request to Apple's servers.
     */
    fun handleErrorResponse(response: AppleReceiptExchangeHttpClientAdapter.Response) {}
}

/**
 * Implementation of [ReceiptExchange].
 *
 * @throws ReceiptExchangeException
 */
internal class ReceiptExchangeImpl(
    override val appleJwsGenerator: AppleJwsGenerator,
    override val receiptValidator: ReceiptValidator,
    override val appleReceiptExchangeHttpClientAdapter: AppleReceiptExchangeHttpClientAdapter,
    override val appleDeviceCheckUrl: URI,
    override val sanityChecks: Boolean,
) : ReceiptExchange
