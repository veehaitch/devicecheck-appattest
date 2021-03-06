package ch.veehait.devicecheck.appattest.util

import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt16
import ch.veehait.devicecheck.appattest.util.Extensions.readAsUInt32
import ch.veehait.devicecheck.appattest.util.Extensions.toUUID
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.comparables.shouldBeEqualComparingTo
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.longs.shouldBeExactly
import io.kotest.matchers.throwable.shouldHaveMessage
import io.kotest.property.Arb
import io.kotest.property.Exhaustive
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.ints
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

class ExtensionsTest : StringSpec() {
    init {
        // ByteArray.readAsUInt16()
        "Parsing bytes as UInt16 requires array of length 2" {
            checkAll(Exhaustive.ints(0 until 10)) { size ->
                when (size) {
                    2 -> shouldNotThrow<IllegalArgumentException> { ByteArray(size).readAsUInt16() }
                    else -> shouldThrow<IllegalArgumentException> {
                        ByteArray(size).readAsUInt16()
                    } shouldHaveMessage "Expected an unsigned 2 byte integer"
                }
            }
        }

        "Parsing bytes as UInt16 works" {
            checkAll(Arb.int(0, (1 shl 16) - 1)) { value ->
                val arr = ByteBuffer
                    .allocate(4)
                    .putInt(value)
                    .order(ByteOrder.BIG_ENDIAN)
                    .array()
                    .takeLast(2)
                    .toByteArray()
                arr.readAsUInt16() shouldBeExactly value
            }
        }

        // ByteArray.readAsUInt32()
        "Parsing bytes as UInt32 requires array of length 4" {
            checkAll(Exhaustive.ints(0 until 10)) { size ->
                when (size) {
                    4 -> shouldNotThrow<IllegalArgumentException> { ByteArray(size).readAsUInt32() }
                    else -> shouldThrow<IllegalArgumentException> {
                        ByteArray(size).readAsUInt32()
                    } shouldHaveMessage "Expected an unsigned 4 byte integer"
                }
            }
        }

        "Parsing bytes as UInt32 works" {
            checkAll(Arb.long(0L, (1L shl 32) - 1)) { value ->
                val arr = ByteBuffer
                    .allocate(8)
                    .putLong(value)
                    .order(ByteOrder.BIG_ENDIAN)
                    .array()
                    .takeLast(4)
                    .toByteArray()
                arr.readAsUInt32() shouldBeExactly value
            }
        }

        // ByteArray.toUUID()
        "Parsing bytes as UUID requires array of maximum length 16" {
            checkAll(Exhaustive.ints(0 until 32)) { size ->
                when {
                    size <= 16 -> shouldNotThrow<IllegalArgumentException> { ByteArray(size).toUUID() }
                    else -> shouldThrow<IllegalArgumentException> {
                        ByteArray(size).toUUID()
                    } shouldHaveMessage "Byte array must not contain more than 16 bytes"
                }
            }
        }

        "Parsing bytes as UUID works" {
            checkAll(Arb.string()) { value ->
                val uuid = UUID.nameUUIDFromBytes(value.toByteArray())
                val arr = uuid.let {
                    ByteBuffer.allocate(16)
                        .putLong(it.mostSignificantBits)
                        .putLong(it.leastSignificantBits)
                }.order(ByteOrder.BIG_ENDIAN).array()

                arr.toUUID() shouldBeEqualComparingTo uuid
            }
        }
    }
}
