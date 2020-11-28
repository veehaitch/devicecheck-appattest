package ch.veehait.devicecheck.appattest

import io.kotest.core.config.AbstractProjectConfig

@Suppress("unused")
object KotestConfig : AbstractProjectConfig() {
    override val parallelism = Runtime.getRuntime().availableProcessors()
}
