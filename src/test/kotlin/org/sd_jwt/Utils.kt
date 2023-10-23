package org.sd_jwt

import com.nimbusds.jose.jwk.JWK
import org.json.JSONArray
import kotlin.test.assertEquals

data class TestConfig(
    val trustedIssuers: Map<String, String>,
    val signer: SdJwtSigner,
    val issuer: String,
    val verifier: String?,
    val nonce: String?,
    val holderKey: JWK?,
    val name: String
)

inline fun <reified T>  testRoutine(
    expectedClaimsKeys: List<String>,
    expectedClaims: T,
    claims: T,
    discloseStructure: T?,
    releaseClaims: T,
    testConfig: TestConfig
) {
    println("\n====================================================")
    println(testConfig.name)
    println("====================================================\n")

    // Initialization
    val holderPubKey = testConfig.holderKey?.toPublicJWK()

    val credentialGen = createCredential(claims, testConfig.signer, holderPubKey, discloseStructure)

    println("====================== Issuer ======================")
    println("Generated credential: $credentialGen")

    val presentationGen = createPresentation(credentialGen, releaseClaims, testConfig.verifier, testConfig.nonce, testConfig.holderKey)

    println("====================== Wallet ======================")
    println("Generated presentation: $presentationGen")

    // Verify presentation
    checkDisclosedDisclosures(presentationGen, expectedClaimsKeys)

    // Raise an error if there is no holder binding, aud or nonce and the presentation does not end with a ~ character
    if ((holderPubKey == null && testConfig.verifier == null && testConfig.nonce == null) && !presentationGen.endsWith("~")) {
        throw Exception("Presentation without holder binding is missing '~' at the end")
    }

    val verifiedCredentialGen = verifyPresentation<T>(presentationGen, testConfig.trustedIssuers,testConfig.nonce, testConfig.verifier,
        holderPubKey != null
    )

    println("===================== Verifier =====================")
    println("Verified credential: $verifiedCredentialGen\n")

    // Verify parsed credential
    assertEquals(expectedClaims, verifiedCredentialGen)
}



fun checkDisclosedDisclosures(presentation: String, expectedClaimsKeys: List<String>) {
    val presentationParts = presentation.split(SEPARATOR)
    assertEquals(expectedClaimsKeys.size, presentationParts.size - 2)
    for (disclosure in presentationParts.subList(1, presentationParts.size - 1)) {
        val disclosureJson = JSONArray(b64Decode(disclosure))
        if (!expectedClaimsKeys.contains(disclosureJson[1])) {
            throw Exception("Unexpected disclosure: $disclosure")
        }
    }
}

fun booleanToInt(b: Boolean) = if (b) 1 else 0
