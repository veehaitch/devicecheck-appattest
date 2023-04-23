package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.common.EqualsVerifierPrefabValues
import io.kotest.core.spec.style.FreeSpec
import nl.jqno.equalsverifier.EqualsVerifier
import java.security.cert.X509Certificate

class ReceiptTest : FreeSpec() {
    init {
        "equals/hashCode" - {
            "Receipt" {
                EqualsVerifier.forClass(Receipt::class.java)
                    .withPrefabValues(
                        X509Certificate::class.java,
                        EqualsVerifierPrefabValues.X509Certificates.red,
                        EqualsVerifierPrefabValues.X509Certificates.blue,
                    )
                    .verify()
            }

            "Receipt.Payload" {
                EqualsVerifier.forClass(Receipt.Payload::class.java)
                    .withPrefabValues(
                        X509Certificate::class.java,
                        EqualsVerifierPrefabValues.X509Certificates.red,
                        EqualsVerifierPrefabValues.X509Certificates.blue,
                    )
                    .verify()
            }

            "Receipt.AttributeSequence" {
                EqualsVerifier.forClass(Receipt.AttributeSequence::class.java).verify()
            }

            "Receipt.AttributeType" {
                EqualsVerifier.forClass(Receipt.AttributeType::class.java).verify()
            }

            "Receipt.Type" {
                EqualsVerifier.forClass(Receipt.Type::class.java).verify()
            }
        }
    }
}
