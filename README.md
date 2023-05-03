# SD-JWT Implementation in Kotlin

This is a Kotlin implementation of the [Selective Disclosure for JWTs](https://github.com/oauthstuff/draft-selective-disclosure-jwt)
spec using the [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) 
library.

Up to date with draft version: [**04**](https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html)

## Checking Out the Implementation

In the [Debugging.kt](src/test/kotlin/org/sd_jwt/Debugging.kt) file 
there are examples that show how the library can be used
on the issuance, wallet and verifier side.

### Running the Examples

#### First Possibility

If you have Docker installed you can simply run:

1. ``docker build -t sd-jwt .``
2. ``docker run -it --rm sd-jwt``

#### Second Possibility (Linux)

1. Install Java version 17 or newer (e.g. ``sudo apt install -y openjdk-17-jdk``)
2. Run tests with the gradle wrapper: ``./gradlew test --tests SdJwtKtTest -i -PossrhUsername= -PossrhPassword=``

## Import into Gradle Project

**Note: The current version is not yet available on Maven Central. 
It will probably be published under the version 0.1.0**

*build.gradle*
```groovy
plugins {
    /* ... */
    id 'org.jetbrains.kotlin.plugin.serialization' version '1.8.10'
}

dependencies {
    /* ... */
    implementation 'org.sd-jwt:sd-jwt-kotlin:0.0.0'

    // https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
    implementation("com.nimbusds:nimbus-jose-jwt:9.30.1")
    // For ED25519 key pairs
    implementation("com.google.crypto.tink:tink:1.7.0")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.4.1")
}
```

## Simple Library Usage

### Initialization

First you need to define your credential as a 
[kotlinx serializable](https://github.com/Kotlin/kotlinx.serialization) 
data class.

```kotlin
@Serializable
private data class SimpleTestCredential(
    val iss: String,
    @SerialName("given_name") val givenName: String? = null,
    @SerialName("family_name") val familyName: String? = null,
    val email: String? = null,
    val b: Boolean? = null,
    val age: Int? = null
)
```

Then you need a few variables to get started.

```kotlin
val issuer = "http://issuer.example.com"

val issuerKeyJson = """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
val issuerKey = OctetKeyPair.parse(issuerKeyJson)

val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())
```

### Issuer Creating the Credential

```kotlin
val claims = SimpleTestCredential(iss = issuer, "Alice", "Wonderland", "alice@example.com", false, 21)
val discloseStructure = SimpleTestCredential(iss = "") // This  is required so that 'iss' is not hidden
val credential = createCredential(claims, issuerKey, discloseStructure = discloseStructure)
```

### Wallet Creating the Presentation

```kotlin
val releaseClaims = SimpleTestCredential(iss = "", givenName = "", email = "", age = 0) // Non-null claims will be revealed
val presentation = createPresentation(credential, releaseClaims)
```

### Verifier Parsing and Verifying the Credential

```kotlin
val verifiedSimpleTestCredential = verifyPresentation<SimpleTestCredential>(
        presentation, 
        trustedIssuers, 
        verifyHolderBinding = false
    )
```

## Advanced Library Usage

This code show  how to
- use holder binding
- create a structured SD-JWT
- create recursively disclosable claims (add HIDE_NAME to the @SerialName annotation)
- add custom header fields to the SD-JWT
```kotlin
@Serializable
data class CredentialSubject(
    @SerialName("given_name") val givenName: String? = null,
    @SerialName("family_name") val familyName: String? = null,
    val email: String? = null
)

@Serializable
data class EmailCredential(
    val type: String,
    val iat: Long,
    val exp: Long,
    val iss: String,
    // Make this object recursively discloseable
    @SerialName(HIDE_NAME + "credentialSubject") val credentialSubject: CredentialSubject? = null 
)

val issuerKey = ECKeyGenerator(Curve.P_256)
    .keyID("Issuer")
    .generate()

val holderKey = ECKeyGenerator(Curve.P_256)
    .keyID("Holder")
    .generate()

val issuer = "did:jwk:${b64Encoder(issuerKey.toPublicJWK().toJSONString())}"

val trustedIssuers = mapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

val userClaims = EmailCredential(
    type = "VerifiedEMail",
    iat = Date.from(Instant.now()).time / 1000,
    exp = Date.from(Instant.now().plusSeconds(3600 * 48)).time / 1000,
    iss = issuer,
    credentialSubject = CredentialSubject(
        givenName = "Alice",
        familyName = "Wonderland",
        email = "alice@example.com"
    )
)

// Each non-null variable will be separately disclosed. 
// Primitive types that are not null will be in plain text in the SD-JWT.
val discloseStructure = EmailCredential(type = "", iat = 0, exp = 0, iss = "", credentialSubject = CredentialSubject())

// Add custom header fields to the SD-JWT
val header = SdJwtHeader(JOSEObjectType("vc+sd-jwt"), "credential-claims-set+json")

/***************** Create Credential *****************/
val credential = createCredential(userClaims, issuerKey, holderKey.toPublicJWK(), discloseStructure, sdJwtHeader = header)

/**************** Create Presentation ****************/
val releaseClaims = EmailCredential(type = "", iat = 0, exp = 0, iss = "", credentialSubject = CredentialSubject(email = ""))
val presentation = createPresentation(credential, releaseClaims, "https://nextcloud.example.com", "1234", holderKey)

/**************** Verify Presentation ****************/
val verifiedEmailCredential = verifyPresentation<EmailCredential>(
        presentation,
        trustedIssuers,
        "1234",
        "https://nextcloud.example.com",
        true
    )
```
