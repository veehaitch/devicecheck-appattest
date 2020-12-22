# Apple App Attest Validation

[![Build status](https://img.shields.io/github/workflow/status/veehaitch/devicecheck-appattest/CI%20Build)](https://github.com/veehaitch/devicecheck-appattest/actions?query=workflow%3A%22CI+Build%22)
[![Code coverage](https://img.shields.io/codecov/c/github/veehaitch/devicecheck-appattest)](https://app.codecov.io/gh/veehaitch/devicecheck-appattest/branch/main)
[![License](https://img.shields.io/github/license/veehaitch/devicecheck-appattest)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Written in Kotlin](https://img.shields.io/badge/code-kotlin-F8873C)](https://kotlinlang.org/)
![JVM 11 required](https://img.shields.io/badge/jvm-11-blue)

Server-side library to validate the authenticity of Apple App Attest artifacts, including 
1. attestation statements,
2. assertions, and
3. receipts (plus requesting a new one from Apple). 

The project targets the JVM in version 11 or later. The library is written purely in Kotlin while leveraging coroutines
for asynchronous execution where meaningful. The implementation relies on only two third party dependencies:
[Bouncy Castle](http://bouncycastle.org) (CMS, ASN.1 parsing) and [Jackson](https://github.com/FasterXML/jackson) 
(CBOR decoding). The software is available under the conditions of the Apache 2.0 license enabling its usage in most
circumstances.

The implementation follows the steps outlined in the articles ["Validating Apps That Connect to Your Server"](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)
and ["Assessing Fraud Risk"](https://developer.apple.com/documentation/devicecheck/assessing_fraud_risk) at Apple Developer.

## Usage

### Verify the Attestation

An iOS app creates an `attestationObject` for a key created through `DCAppAttestService.generateKey()` 
by calling `DCAppAttestService.attestKey()`. Make sure the `clientDataHash` comprises a payload which includes a
challenge you created within your backend prior to the app's call to `attestKey`. A good challenge is created
randomly, only used once (i.e., one challenge per attestation) and large enough to prevent guessing.

```swift
let service = DCAppAttestService.shared

service.generateKey { keyId, error in
    guard error == nil else { /* Handle the error. */ }
    // Store keyId for subsequent operations.
}

service.attestKey(keyId, clientDataHash: hash) { attestationObject, error in
    guard error == nil else { /* Handle error and return. */ }
    // Send attestationObject to your server for verification.
}
```

The server implementation receives the `attestationObject`, e.g., Base64 encoded, and the `keyId`. The `keyId` returned 
from `DCAppAttestService.generateKey()` is already Base64 encoded (or more precisely, it is the Base64 encoded SHA-256
digest of the public key of the generated key).

To validate the authenticity of the `attestationObject`, instantiate an `AttestationValidator` for the `App` which 
calls `DCAppAttestService`. 

```kotlin
// Create an instance of AppleAppAttest specific to a given iOS app, development team and
// Apple Appattest environment
val appleAppAttest = AppleAppAttest(
    app = App("6MURL8TA57", "de.vincent-haupert.apple-appattest-poc"),
    appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
)

// Create an AttestationValidator instance
val attestationValidator = appleAppAttest.createAttestationValidator()

// Validate a single attestation object. Throws an AttestationException if a validation
// error occurs.
val result: ValidatedAttestation = attestationValidator.validate(
    attestationObject = Base64.getDecoder().decode("o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F ..."),
    keyIdBase64 = "XGr5wqmUab/9M4b5vxa6KkPOigfeEWDaw7tuK02aJ6c=",
    serverChallenge = "wurzelpfropf".toByteArray(),
)
```

If the method call returns, the validation has passed and you can now trust the
[returned result](https://github.com/veehaitch/devicecheck-appattest/blob/main/src/main/kotlin/ch/veehait/devicecheck/appattest/attestation/ValidatedAttestation.kt)
which contains references to the attestation certificate and the verified receipt.
You use the public key of the attestation certificate for the verification of
assertions and the receipt for obtaining a fraud risk metric.

Also refer to [AttestationValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/attestation/AttestationValidatorTest.kt).

### Verify the Assertion

As soon as you validated the attestation statement, your app may leverage the attested public key to create assertions
for arbitrary payloads using the App Attest service:

```swift
service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertionObject, error in
    guard error == nil else { /* Handle the error. */ }
    // Send the assertion and request to your server.
}
```

It is worthwhile to note that the returned `assertionObject` does not contain the `keyId` by itself. You have to include
it in the data which accompanies the `assertionObject`. Make sure to not rely on the `keyId` to establish a link to any
identity in your systems _prior to verifying_ the assertion's authenticity by calling `AssertionValidator.validate()`:

```kotlin
// Initialize AppleAppAttest as above

val assertionChallengeValidator = object : AssertionChallengeValidator {
    override fun validate(
        assertionObj: Assertion,
        clientData: ByteArray,
        attestationPublicKey: ECPublicKey,
        challenge: ByteArray,
    ): Boolean = TODO("Your application specific challenge validation routine")
}

val assertionValidator = appleAppAttest.createAssertionValidator(
    assertionChallengeValidator
)

val assertion = assertionValidator.validate(/* ... */)
```

If the call returns, the app successfully proved control of the attested device. Make sure to include a challenge which
suits the security demands of your service. A safe approach is to issue server-side per-assertion challenges, similar
to those created for the initial attestation statement (see above).

Also refer to [AssertionValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/assertion/AssertionValidatorTest.kt)

### Assess Fraud Risk with Receipts

See [ReceiptValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/receipt/ReceiptValidatorTest.kt) and 
[ReceiptExchangeTest](src/test/kotlin/ch/veehait/devicecheck/appattest/receipt/ReceiptExchangeTest.kt).

## Contributions

Your contributions are welcome! Just submit a pull request. Also, if you have a question, feel free to open an issue.

## License

[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html)
