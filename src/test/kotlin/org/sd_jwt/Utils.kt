package org.sd_jwt

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import kotlin.test.assertEquals
import kotlin.test.assertTrue

data class TestConfig(
    val trustedIssuers: Map<String, String>,
    val issuerSigner: SdJwtSigner,
    val issuer: String,
    val verifier: String?,
    val nonce: String?,
    val holderSigner: SdJwtSigner?,
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
    val expectedClaimsJson = JSONObject(Json.encodeToString(expectedClaims))
    val claimsJson = JSONObject(Json.encodeToString(claims))
    val discloseStructureJson = JSONObject(Json.encodeToString(discloseStructure))
    val releaseClaimsJson = JSONObject(Json.encodeToString(releaseClaims))

    testRoutine(
        expectedClaimsKeys = expectedClaimsKeys,
        expectedClaims = expectedClaimsJson,
        claims = claimsJson,
        discloseStructure = discloseStructureJson,
        releaseClaims = releaseClaimsJson,
        testConfig = testConfig,
        compareSingleValues = true
    )
}

fun testRoutine(
    expectedClaimsKeys: List<String>,
    expectedClaims: JSONObject,
    claims: JSONObject,
    discloseStructure: JSONObject,
    releaseClaims: JSONObject,
    testConfig: TestConfig,
    compareSingleValues: Boolean = false
) {
    println("\n====================================================")
    println(testConfig.name)
    println("====================================================\n")

    // Initialization
    val holderPubKey = testConfig.holderSigner?.getPublicJWK()

    val credentialGen = createCredential(
        userClaims = claims,
        signer = testConfig.issuerSigner,
        holderPubKey = holderPubKey,
        discloseStructure = discloseStructure
    )

    println("====================== Issuer ======================")
    println("Generated credential: $credentialGen")

    val presentationGen =
        createPresentation(credentialGen, releaseClaims, testConfig.verifier, testConfig.nonce, testConfig.holderSigner)

    println("====================== Wallet ======================")
    println("Generated presentation: $presentationGen")

    // Verify presentation
    checkDisclosedDisclosures(presentationGen, expectedClaimsKeys)

    // Raise an error if there is no holder binding, aud or nonce and the presentation does not end with a ~ character
    if ((holderPubKey == null && testConfig.verifier == null && testConfig.nonce == null) && !presentationGen.endsWith("~")) {
        throw Exception("Presentation without holder binding is missing '~' at the end")
    }

    val verifiedCredentialGen = verifyPresentation(
        presentationGen, TrustedIssuersSdJwtVerifier(testConfig.trustedIssuers), testConfig.nonce, testConfig.verifier,
        holderPubKey != null
    )

    println("===================== Verifier =====================")
    println("Verified credential: $verifiedCredentialGen\n")

    if(!compareSingleValues){
        // Verify parsed credential
        assertEquals(expectedClaims, verifiedCredentialGen)
    }
    else{
        // verifies 2 (unsorted) JSONObject are matching
        assertTrue {
            expectedClaims.toMap().forEach {
                if (verifiedCredentialGen[it.key].toString().isEmpty()) false // should have key
                if (verifiedCredentialGen[it.key] != it.value) false // values should match for key
            }

            true
        }
    }
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
