package ch.veehait.devicecheck.appattest

/**
 * The [App] that leverages the DCAppAttest service.
 *
 * @param appTeamIdentifier The 10-digit identifier of the team who signs your app, as denoted on
 *   https://developer.apple.com/account. Also known as app identifier prefix (without the trailing dot).
 * @param appBundleIdentifier Your app’s CFBundleIdentifier value. Also known as app identifier suffix.
 */
data class App(
    val teamIdentifier: String,
    val bundleIdentifier: String,
) {
    companion object {
        const val APPLE_TEAM_IDENTIFIER_LENGTH = 10
    }

    init {
        if (teamIdentifier.length != APPLE_TEAM_IDENTIFIER_LENGTH) {
            throw IllegalArgumentException("The Apple team identifier must consist of exactly 10 digits")
        }
    }

    val appIdentifier: String = "$teamIdentifier.$bundleIdentifier"

    override fun toString() = appIdentifier
}
