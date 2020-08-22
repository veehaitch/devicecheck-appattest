package ch.veehait.devicecheck.appattest

fun <T> Class<T>.readTextResource(name: String, commentLinePrefix: String = "#"): String =
    getResource(name).readText().split("\n").filterNot { it.startsWith(commentLinePrefix) }.joinToString("\n")
