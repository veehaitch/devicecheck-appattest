package ch.veehait.devicecheck.appattest

import io.kotest.core.config.AbstractProjectConfig
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

@Suppress("unused")
object KotestConfig : AbstractProjectConfig() {
    override val parallelism = Runtime.getRuntime().availableProcessors()

    init {
        Security.addProvider(BouncyCastleProvider())
    }
}
