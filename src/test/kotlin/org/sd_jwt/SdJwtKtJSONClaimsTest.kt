package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import org.json.JSONObject
import org.junit.jupiter.api.Test

class SdJwtKtJSONClaimsTest {
    private val verifier = "http://verifier.example.com"
    private val issuer = "http://issuer.example.com"

    private val issuerKeyJson =
        """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
    private val issuerKey = OctetKeyPair.parse(issuerKeyJson)
    private val holderKeyJson =
        """{"kty":"OKP","d":"8G6whDz1owU1k7-TqtP3xEMasdI3t3j2AvpvXVwwrHQ","crv":"Ed25519","kid":"HolderKey","x":"s6gVLINLcCGhGEDTf_v1zMluLZcXj4GOXAfQlOWZM9Q"}"""
    private val holderKey = OctetKeyPair.parse(holderKeyJson)

    private val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

    private val nonce = "12345"

    private val testConfig =
        TestConfig(
            trustedIssuers = trustedIssuers,
            issuerKey = issuerKey,
            issuer = issuer,
            verifier = verifier,
            nonce = nonce,
            holderKey = holderKey,
            name = "JSONObject Credential"
        )


    private val simpleCredentialUserClaims = JSONObject(
        mapOf(
            Pair("iss", "$issuer"),
            Pair("iat", "54678098"),
            Pair("first_name", "Max"),
            Pair("last_name", "Muster"),
            Pair("age", "33"),
            Pair("address", "Musterstr. 15, 75759, DE")
        )
    )

    private val complexCredentialUserClaims = JSONObject(
        mapOf(
            Pair("iss", "$issuer"),
            Pair("iat", "54678098"),
            Pair("first_name", "Max"),
            Pair("last_name", "Muster"),
            Pair("age", "33"),
            Pair(
                "address", mapOf(
                    Pair("street", "Musterstr. 15"),
                    Pair("code", "75759"),
                    Pair("country", "DE")
                )
            )
        )
    )

    @Test
    fun createSimpleCredentialAsJson_partly_disclosed_ok() {
        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("iat", "")
            )
        )

        val releaseClaims = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("age", "")
            )
        )

        val expectedClaims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("age", "33")
            )
        )

        val expectedClaimsKeys = listOf(
            "first_name",
            "age",
        )

        testRoutine(
            expectedClaimsKeys = expectedClaimsKeys,
            expectedClaims = expectedClaims,
            claims = simpleCredentialUserClaims,
            discloseStructure = discloseStructure,
            releaseClaims = releaseClaims,
            testConfig = testConfig,
            compareSingleValues = true
        )
    }

    @Test
    fun shouldIgnoreExtraClaimInDisclosureStructure() {
        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("iat", ""),
                Pair("extra", "")
            )
        )

        val releaseClaims = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("age", "")
            )
        )

        val expectedClaims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("iat", "54678098"),
                Pair("first_name", "Max"),
                Pair("age", "33")
            )
        )

        val expectedClaimsKeys = listOf(
            "first_name",
            "age",
        )

        testRoutine(
            expectedClaimsKeys = expectedClaimsKeys,
            expectedClaims = expectedClaims,
            claims = simpleCredentialUserClaims,
            discloseStructure = discloseStructure,
            releaseClaims = releaseClaims,
            testConfig = testConfig,
            compareSingleValues = true
        )
    }

    @Test
    fun complexStructureShouldIgnoreExtraClaimInDisclosureStructure() {
        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("iat", ""),
                Pair(
                    "address", mapOf(
                        Pair("country", ""),
                        Pair("extra", "")
                    )
                )
            )
        )

        val releaseClaims = JSONObject(
            mapOf(
                Pair("first_name", ""),
                Pair("age", "")
            )
        )

        val expectedClaims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("iat", "54678098"),
                Pair("first_name", "Max"),
                Pair("age", "33"),
                Pair("address", mapOf(
                    Pair("country", "DE")
                ))
            )
        )

        val expectedClaimsKeys = listOf(
            "first_name",
            "age",
        )

        testRoutine(
            expectedClaimsKeys = expectedClaimsKeys,
            expectedClaims = expectedClaims,
            claims = complexCredentialUserClaims,
            discloseStructure = discloseStructure,
            releaseClaims = releaseClaims,
            testConfig = testConfig,
            compareSingleValues = true
        )
    }
}