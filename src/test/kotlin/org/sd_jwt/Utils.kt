package org.sd_jwt

import com.nimbusds.jose.jwk.JWK
import org.json.JSONArray
import org.json.JSONObject
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

data class TestConfig(
    val trustedIssuers: Map<String, String>,
    val issuerKey: JWK,
    val issuer: String,
    val verifier: String,
    val nonce: String,
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

    val credentialGen = createCredential(claims, holderPubKey, testConfig.issuer, testConfig.issuerKey, discloseStructure)

    println("====================== Issuer ======================")
    println("Generated credential: $credentialGen")

    val presentationGen = createPresentation(credentialGen, releaseClaims, testConfig.verifier, testConfig.nonce, testConfig.holderKey)

    // Verify presentation
    checkDisclosedDisclosures(presentationGen, expectedClaimsKeys, testConfig.holderKey != null)

    println("====================== Wallet ======================")
    println("Generated presentation: $presentationGen")

    val verifiedCredentialGen = verifyPresentation<T>(presentationGen, testConfig.trustedIssuers,testConfig.nonce, testConfig.verifier,
        holderPubKey != null
    )

    println("===================== Verifier =====================")
    println("Verified credential: $verifiedCredentialGen\n")

    // Verify parsed credential
    assertEquals(expectedClaims, verifiedCredentialGen)
}



fun checkDisclosedDisclosures(presentation: String, expectedClaimsKeys: List<String>, holderBinding: Boolean) {
    val presentationParts = presentation.split(SEPARATOR)
    assertEquals(expectedClaimsKeys.size, presentationParts.size - 1 - booleanToInt(holderBinding))
    for (disclosure in presentationParts.subList(1, presentationParts.size - booleanToInt(holderBinding))) {
        val disclosureJson = JSONArray(b64Decode(disclosure))
        if (!expectedClaimsKeys.contains(disclosureJson[1])) {
            throw Exception("Unexpected disclosure: $disclosure")
        }
    }
}

fun compareSvcClaim(s1: Any?, s2: Any) {
    assertTrue(s1 is String)
    assertTrue(s2 is String)
    val s1Parsed = JSONArray(s1)
    val s2Parsed = JSONArray(s2)
    assertEquals(s1Parsed.length(), s2Parsed.length())
    assertEquals(s1Parsed[1].toString(), s2Parsed[1].toString())
}

fun assertSVC(expected: String, actual: String) {
    val expectedJson = JSONObject(b64Decode(expected))
    val actualJson = JSONObject(b64Decode(actual))

    walkByStructure(expectedJson, actualJson, ::compareSvcClaim)
    walkByStructure(actualJson, expectedJson, ::compareSvcClaim)
}

fun compareSdDigest(d1: Any?, d2: Any) {
    assertTrue(d1 is String)
    assertTrue(d2 is String)
}

fun assertSdJWT(expected: String, actual: String) {
    val expectedSplit = expected.split(".")
    val expectedHeaderJson = JSONObject(b64Decode(expectedSplit[0]))
    val expectedBodyJson = JSONObject(b64Decode(expectedSplit[1]))
    val actualSplit = actual.split(".")
    val actualBodyJson = JSONObject(b64Decode(actualSplit[1]))
    val actualHeaderJson = JSONObject(b64Decode( actualSplit[0]))

    // Verify header
    assertEquals(expectedHeaderJson.opt("alg"), actualHeaderJson.opt("alg"))

    // Verify body
    assertEquals(expectedBodyJson.opt("sd_hash_alg"), actualBodyJson.opt("sd_hash_alg"))
    assertEquals(expectedBodyJson.opt("iss"), actualBodyJson.opt("iss"))
    if (expectedBodyJson.opt("cnf") is JSONObject && actualBodyJson.opt("cnf") is JSONObject) {
        assertEquals(expectedBodyJson.opt("cnf").toString(), actualBodyJson.opt("cnf").toString())
    } else {
        assertNull(expectedBodyJson.opt("cnf"))
        assertNull(actualBodyJson.opt("cnf"))
    }
    assertTrue(actualBodyJson.opt("iat") is Int)

    // Walk over the digests and check that they have the same structure
    assertTrue(expectedBodyJson.opt("sd_digests") is JSONObject)
    assertTrue(actualBodyJson.opt("sd_digests") is JSONObject)

    walkByStructure(
        expectedBodyJson.getJSONObject("sd_digests"),
        actualBodyJson.getJSONObject("sd_digests"),
        ::compareSdDigest
    )
    walkByStructure(
        actualBodyJson.getJSONObject("sd_digests"),
        expectedBodyJson.getJSONObject("sd_digests"),
        ::compareSdDigest
    )
}

fun assertSdJwtR(expected: String, actual: String) {
    val expectedSplit = expected.split(".")
    val expectedHeaderJson = JSONObject(b64Decode(expectedSplit[0]))
    val expectedBodyJson = JSONObject(b64Decode(expectedSplit[1]))
    val actualSplit = actual.split(".")
    val actualBodyJson = JSONObject(b64Decode(actualSplit[1]))
    val actualHeaderJson = JSONObject(b64Decode( actualSplit[0]))

    // Verify header
    assertEquals(expectedHeaderJson.opt("alg"), actualHeaderJson.opt("alg"))

    // Verify body
    assertEquals(expectedBodyJson.opt("aud"), actualBodyJson.opt("aud"))
    assertEquals(expectedBodyJson.opt("nonce"), actualBodyJson.opt("nonce"))

    // Walk over the digests and check that they have the same structure
    assertTrue(expectedBodyJson.opt("sd_release") is JSONObject)
    assertTrue(actualBodyJson.opt("sd_release") is JSONObject)

    walkByStructure(
        expectedBodyJson.getJSONObject("sd_release"),
        actualBodyJson.getJSONObject("sd_release"),
        ::compareSvcClaim
    )
    walkByStructure(
        actualBodyJson.getJSONObject("sd_release"),
        expectedBodyJson.getJSONObject("sd_release"),
        ::compareSvcClaim
    )
}

fun splitCredential(credential: String): Pair<String, String> {
    val expectedSplit = credential.split(".")
    assertEquals(4, expectedSplit.size)
    val sdJWT = "${expectedSplit[0]}.${expectedSplit[1]}.${expectedSplit[2]}"
    val svc = expectedSplit[3]
    return Pair(sdJWT, svc)
}

fun splitPresentation(presentation: String): Pair<String, String> {
    val split = presentation.split(".")
    val sdJwt = "${split[0]}.${split[1]}.${split[2]}"
    val sdJwtR = "${split[3]}.${split[4]}.${split[5]}"
    return Pair(sdJwt, sdJwtR)
}