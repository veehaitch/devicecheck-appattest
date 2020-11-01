package ch.veehait.devicecheck.appattest.common

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

class AppTest : StringSpec() {
    init {
        "Builds app identifier correctly" {
            val app = App("wurzelpfro", "pf")
            app.teamIdentifier shouldBe "wurzelpfro"
            app.bundleIdentifier shouldBe "pf"
            app.appIdentifier shouldBe "wurzelpfro.pf"
        }

        "Returns app identifier as string" {
            val app = App("wurzelpfro", "pf")
            app.appIdentifier shouldBe app.toString()
        }

        "Asserts that team identifier is of length 10" {
            shouldThrow<IllegalArgumentException> {
                App("A".repeat(9), "test")
            }
            shouldThrow<IllegalArgumentException> {
                App("A".repeat(11), "test")
            }
            App("A".repeat(10), "test")
        }

        "Asserts that bundle identifier is not empty" {
            shouldThrow<IllegalArgumentException> {
                App("A".repeat(10), "")
            }
            App("A".repeat(10), "test")
        }
    }
}
