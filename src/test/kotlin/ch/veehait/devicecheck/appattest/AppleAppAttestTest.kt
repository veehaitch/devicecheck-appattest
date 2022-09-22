package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.CertUtils.toPEM
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.receipt.AppleJwsGeneratorImpl
import ch.veehait.devicecheck.appattest.receipt.ReceiptExchange
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class AppleAppAttestTest : FreeSpec() {
    init {
        "Sets correct Apple server URL for ReceiptExchange depending on environment" - {
            AppleAppAttestEnvironment.values().forEach { env ->
                env.name {
                    val receiptExchange = AppleAppAttest(
                        app = App("WURZELPFRO", "PF"),
                        appleAppAttestEnvironment = env
                    ).createReceiptExchange(
                        appleJwsGenerator = AppleJwsGeneratorImpl(
                            teamIdentifier = "WURZELPFRO",
                            keyIdentifier = "wurzelpfropf",
                            privateKeyPem = CertUtils.generateP256KeyPair().private.toPEM()
                        )
                    )

                    val expectedUrl = when (env) {
                        AppleAppAttestEnvironment.DEVELOPMENT -> {
                            ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL
                        }
                        AppleAppAttestEnvironment.PRODUCTION -> {
                            ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL
                        }
                    }

                    receiptExchange.appleDeviceCheckUrl shouldBe expectedUrl
                }
            }
        }
    }
}
