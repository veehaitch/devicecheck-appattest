# Apple App Attest Validation

![Build status](https://github.com/veehaitch/devicecheck-appattest/workflows/Gradle%2FJVM%20CI/badge.svg)
![Code coverage](https://codecov.io/gh/veehaitch/devicecheck-appattest/branch/main/graphs/badge.svg?branch=main)

Proof of concept, server-side library for validating the authenticity of Apple App Attest artifacts, including 
1. attestation statements,
2. assertions, and
3. receipts.

The implementation follows the steps outlined in the articles ["Validating Apps That Connect to Your Server"](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)
and ["Assessing Fraud Risk"](https://developer.apple.com/documentation/devicecheck/assessing_fraud_risk) at Apple Developer. 

## Usage

### Verify the Attestation

An iOS app creates an `attestationObject` for a key created through `DCAppAttestService#generateKey` 
by calling `DCAppAttestService#attestKey`. Make sure the `clientDataHash` comprises a payload which includes a
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
from `DCAppAttestService#generateKey` is already Base64 encoded (or more precisely, it is the Base64 encoded SHA-256
digest of the public key of the generated key).

To validate the authenticity of the `attestationObject`, instantiate an `AttestationValidator` for the `App` which 
calls `DCAppAttestService`. 

```kotlin
// Create an AttestationValidator instance specific to a given iOS app and development team
val attestationValidator: AttestationValidator = AttestationValidatorImpl(
    app = App("6MURL8TA57", "de.vincent-haupert.apple-appattest-poc"),
)

// Validate a single attestation object. Throws an AttestationException if a validation error occurs.
val result: AppleAppAttestValidationResponse = attestationValidator.validate(
    attestationObject = Base64.getDecoder().decode("o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAvYwggLyM ..."),
    keyIdBase64 = "XGr5wqmUab/9M4b5vxa6KkPOigfeEWDaw7tuK02aJ6c=",
    serverChallenge = "wurzelpfropf".toByteArray()
)

// If the method call returns, the validation has passed and you can now trust the returned public key and receipt.
```

Also refer to [AttestationValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/attestation/AttestationValidatorTest.kt).

### Verify the Assertion

See [AssertionValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/assertion/AssertionValidatorTest.kt)

### Assess Fraud Risk with Receipts

See [ReceiptValidatorTest](src/test/kotlin/ch/veehait/devicecheck/appattest/receipt/ReceiptValidatorTest.kt) and 
[ReceiptExchangeTest](src/test/kotlin/ch/veehait/devicecheck/appattest/receipt/ReceiptExchangeTest.kt).

## Building

Just clone this repository

	git clone https://github.com/veehaitch/devicecheck-appattest.git
	
and build using Gradle

	./gradlew build
	
## License

[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html)
