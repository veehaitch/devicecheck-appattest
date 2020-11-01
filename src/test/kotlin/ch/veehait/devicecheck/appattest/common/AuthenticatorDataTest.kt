package ch.veehait.devicecheck.appattest.common

import io.kotest.core.spec.style.StringSpec
import nl.jqno.equalsverifier.EqualsVerifier

class AuthenticatorDataTest : StringSpec() {
    init {
        "AttestedCredentialData: equals/hashCode" {
            EqualsVerifier.forClass(AttestedCredentialData::class.java).verify()
        }

        "AuthenticatorData: equals/hashCode" {
            EqualsVerifier.forClass(AuthenticatorData::class.java).verify()
        }
    }
}
