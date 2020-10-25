package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.Extensions.toBase64
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import java.net.URI
import java.security.interfaces.ECPublicKey

interface ReceiptExchange {
    val appleJwsGenerator: AppleJwsGenerator
    val receiptValidator: ReceiptValidator
    val appleDeviceCheckUrl: URI
    val appleReceiptHttpClientAdapter: AppleReceiptHttpClientAdapter

    companion object {
        val APPLE_DEVICE_CHECK_PRODUCTION_BASE_URL: URI = URI.create(
            "https://data.appattest.apple.com/v1/attestationData"
        )
        val APPLE_DEVICE_CHECK_DEVELOPMENT_BASE_URL: URI = URI.create(
            "https://data-development.appattest.apple.com/v1/attestationData"
        )
    }

    /**
     * Suspending implementation of [trade]
     */
    suspend fun tradeAsync(receiptP7: ByteArray, attestationPublicKey: ECPublicKey): Receipt = coroutineScope {
        // Validate the receipt before sending it to Apple
        val receipt = async { receiptValidator.validateReceipt(receiptP7, attestationPublicKey) }
        val authorizationHeader = async { mapOf("Authorization" to appleJwsGenerator.issueToken()) }

        val response = appleReceiptHttpClientAdapter.post(
            appleDeviceCheckUrl,
            authorizationHeader.await(),
            receipt.await().p7.toBase64().toByteArray(),
        )

        @Suppress("MagicNumber")
        if (response.statusCode != 200) {
            handleErrorResponse(response)
            throw ReceiptExchangeException.HttpError("Caught an error in Apple's response: $response")
        }

        receiptValidator.validateReceipt(response.body.fromBase64(), attestationPublicKey)
    }

    /**
     * Exchange a [receiptP7] for a new one.
     *
     * Also verifies the validity of the passed [receiptP7] and the returned receipt.
     *
     * @param receiptP7 A PKCS#7 receipt obtained in a previous remote call to Apple or from an attestation statement
     * @param attestationPublicKey The public key of the initial attestation statement
     * @return A new receipt superseding the old one
     */
    fun trade(receiptP7: ByteArray, attestationPublicKey: ECPublicKey): Receipt = runBlocking {
        tradeAsync(receiptP7, attestationPublicKey)
    }

    /**
     * Handle any response with a status code not equal to 200 (OK).
     *
     * @param response The response from the request to Apple's servers
     */
    fun handleErrorResponse(response: AppleReceiptHttpClientAdapter.Response) {}
}

class ReceiptExchangeImpl(
    override val appleJwsGenerator: AppleJwsGenerator,
    override val receiptValidator: ReceiptValidator,
    override val appleDeviceCheckUrl: URI = ReceiptExchange.APPLE_DEVICE_CHECK_DEVELOPMENT_BASE_URL,
    override val appleReceiptHttpClientAdapter: AppleReceiptHttpClientAdapter = DEFAULT_HTTP_CLIENT_ADAPTER,
) : ReceiptExchange {
    companion object {
        private val DEFAULT_HTTP_CLIENT_ADAPTER = SimpleAppleReceiptHttpClientAdapter()
    }
}
