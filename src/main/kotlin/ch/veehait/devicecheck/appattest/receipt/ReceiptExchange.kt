package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.Extensions.toBase64
import java.net.URI
import java.security.PublicKey

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
     * Exchange a [receiptP7] for a new one.
     *
     * Also verifies the validity of the passed [receiptP7] and the returned receipt.
     *
     * @param receiptP7 A PKCS#7 receipt obtained in a previous remote call to Apple or from an attestation statement
     * @param attestationPublicKey The public key of the initial attestation statement
     * @return A new receipt superseding the old one
     */
    fun trade(receiptP7: ByteArray, attestationPublicKey: PublicKey): Receipt {
        // Validate the receipt before sending it to Apple
        receiptValidator.validateReceipt(receiptP7, attestationPublicKey)

        val response = appleReceiptHttpClientAdapter.post(
            appleDeviceCheckUrl,
            mapOf("Authorization" to appleJwsGenerator.issueToken()),
            receiptP7.toBase64().toByteArray(),
        )

        @Suppress("MagicNumber")
        if (response.statusCode != 200) {
            handleErrorResponse(response)
        }

        return receiptValidator.validateReceipt(response.body.fromBase64(), attestationPublicKey)
    }

    /**
     * Handle any response with a status code not equal to 200 (OK).
     *
     * @param response The response from the request to Apple's servers
     */
    fun handleErrorResponse(response: AppleReceiptHttpClientAdapter.Response) {
        throw ReceiptExchangeException.HttpError("Caught an error in Apple's response: $response")
    }
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
