package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.TestExtensions.encode
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.attestation.AttestationObject
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import nl.jqno.equalsverifier.EqualsVerifier

class AuthenticatorDataTest : FreeSpec() {
    init {
        "equals/hashCode" - {
            "AttestedCredentialData" {
                EqualsVerifier.forClass(AttestedCredentialData::class.java).verify()
            }

            "AuthenticatorData" {
                EqualsVerifier.forClass(AuthenticatorData::class.java).verify()
            }
        }

        "Would read extensions with attestedCredentials" {
            val sample = AttestationSample.all.random()

            val objectReader = TestUtils.cborObjectMapper.readerFor(AttestationObject::class.java)

            val attestationObject: AttestationObject = objectReader.readValue(sample.attestation)
            val authenticatorData = AuthenticatorData.parse(attestationObject.authData)
            val authDataWithExtensions = authenticatorData.copy(
                flags = authenticatorData.flags.plus(AuthenticatorDataFlag.ED),
                extensions = linkedMapOf(
                    "wurzel" to "pfropf"
                ),
            ).encode()

            val authenticatorDataWithExtensions = shouldNotThrowAny {
                AuthenticatorData.parse(authDataWithExtensions)
            }

            authenticatorDataWithExtensions.extensions.shouldNotBeNull()
        }

        "Would read extensions without attestedCredentials" {
            val sample = AttestationSample.all.random()

            val objectReader = TestUtils.cborObjectMapper.readerFor(AttestationObject::class.java)

            val attestationObject: AttestationObject = objectReader.readValue(sample.attestation)
            val authenticatorData = AuthenticatorData.parse(attestationObject.authData)
            val authDataWithExtensions = authenticatorData.copy(
                flags = authenticatorData.flags
                    .plus(AuthenticatorDataFlag.ED)
                    .minus(AuthenticatorDataFlag.AT),
                attestedCredentialData = null,
                extensions = linkedMapOf(
                    "wurzel" to "pfropf"
                ),
            ).encode()

            val authenticatorDataWithExtensions = shouldNotThrowAny {
                AuthenticatorData.parse(authDataWithExtensions)
            }

            authenticatorDataWithExtensions.extensions.shouldNotBeNull()
        }
    }
}
