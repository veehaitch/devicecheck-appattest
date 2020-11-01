package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.util.Extensions.toUUID
import java.util.UUID

/**
 * The environment for an app that uses the App Attest service to validate itself.
 *
 * @property identifier An App Attest–specific constant that indicates whether the attested key belongs to the
 *   development or production environment.
 */
enum class AppleAppAttestEnvironment(private val identifier: String) {
    /**
     * The App Attest sandbox environment that you use to test a device without affecting its risk metrics. Keys you
     * create in the sandbox environment don’t work in the production environment.
     */
    DEVELOPMENT("appattestdevelop"),

    /**
     * The App Attest production environment. Keys you create in the production environment don’t work in the sandbox
     *   environment.
     */
    PRODUCTION("appattest");

    /**
     * The AAGUID representing the environment.
     */
    val aaguid: UUID = identifier.toByteArray().toUUID()
}
