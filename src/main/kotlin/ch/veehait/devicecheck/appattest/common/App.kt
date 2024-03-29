package ch.veehait.devicecheck.appattest.common

/**
 * The [App] that leverages the DCAppAttest service.
 *
 * @param teamIdentifier The 10-digit identifier of the team which signs your app, as denoted on
 *   https://developer.apple.com/account. Also known as app identifier prefix (without the trailing dot).
 * @param bundleIdentifier Your app’s CFBundleIdentifier value. Also known as app identifier suffix.
 */
data class App(
    val teamIdentifier: String,
    val bundleIdentifier: String,
) {
    companion object {
        const val APPLE_TEAM_IDENTIFIER_LENGTH = 10
    }

    init {
        require(teamIdentifier.length == APPLE_TEAM_IDENTIFIER_LENGTH) {
            "The Apple team identifier must consist of exactly 10 digits"
        }

        require(bundleIdentifier.isNotEmpty()) {
            "The Apple bundle identifier must not be empty"
        }
    }

    val appIdentifier: String = "$teamIdentifier.$bundleIdentifier"

    override fun toString() = appIdentifier
}
