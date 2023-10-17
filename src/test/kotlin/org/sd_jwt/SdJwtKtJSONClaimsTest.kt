package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

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

    @Serializable
    private data class Address(
        @SerialName("street_address") val streetAddress: String? = null,
        val locality: String? = null,
        val region: String? = null,
        val country: String? = null,
        @SerialName("zip_code") val zipCode: Int? = null
    )

    @Serializable
    private data class IdCredential(
        val iss: String,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val birthday: String? = null,
        val nicknames: Set<String>? = null,
        val address: Address? = null
    )

    @Test
    fun testAdvancedCredentialStructured_Json_ok() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced Credential Structured")

        val claims = IdCredential(
            issuer,
            givenName = "Alice",
            familyName = "Wonderland",
            email = "alice@example.com",
            birthday = "1940-01-01",
            nicknames = setOf("A", "B"),
            address = Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )

        val claimsJson = JSONObject(Json.encodeToString(claims))

        val discloseStructure = IdCredential(iss = "", address = Address())

        val discloseStructureJson = JSONObject(Json.encodeToString(discloseStructure))

        val releaseClaims = IdCredential(
            iss = "",
            givenName = "",
            familyName = "",
            nicknames = setOf(),
            address = Address(streetAddress = "", locality = "", zipCode = 0)
        )

        val releaseClaimsJson = JSONObject(Json.encodeToString(releaseClaims))

        val expectedClaims = IdCredential(
            iss = issuer,
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address(streetAddress = "123 Main St", locality = "Anytown", zipCode = 123456)
        )

        val expectedClaimsJson = JSONObject(Json.encodeToString(expectedClaims))

        val expectedClaimsKeys = listOf(
            "given_name",
            "family_name",
            "nicknames",
            "street_address",
            "locality",
            "zip_code"
        )

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

    @Test
    fun testCreateSimpleCredentialAsJson_partly_disclosed_ok() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced JSON-String Credential")

        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("address", "Musterstr. 15, 75759, DE")
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", null),
                Pair("last_name", null),
                Pair("age", null),
                Pair("address", null)
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
            claims = claims,
            discloseStructure = discloseStructure,
            releaseClaims = releaseClaims,
            testConfig = testConfig,
            compareSingleValues = true
        )
    }

    @Test
    fun testSimpleCredentialFormat_Json_no_SD_ok() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("address", "Musterstr. 15, 75759, DE")
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("address", "")
            )
        )

        val credential = createCredential(
            userClaims = claims,
            issuerKey = issuerKey,
            discloseStructure = discloseStructure
        )

        val credentialParts = credential.split(SEPARATOR)
        assertEquals(2, credentialParts.size)
        assert(credentialParts[1].isEmpty())
    }

    @Test
    fun testCreateSimpleCredentialAsJson_empty_disclosure_ok() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("address", "Musterstr. 15, 75759, DE")
            )
        )

        val credential = createCredential(
            userClaims = claims,
            issuerKey = issuerKey
        )

        val credentialParts = credential.split(SEPARATOR)
        assertEquals(6, credentialParts.size)
    }

    @Test
    fun testCreateSimpleCredentialAsJson_partly_disclosed_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("address", "Musterstr. 15, 75759, DE")
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("extra", ""),
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.let {
                    assert(
                        it.contains("Structures of userClaims and discloseStructure do not match!")
                    )
                }
            }
    }

    @Test
    fun testCreateSimpleCredentialAsJson_fully_disclosed_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("address", "Musterstr. 15, 75759, DE")
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("extra", ""),
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("address", ""),
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.let {
                    assert(
                        it.contains("Structures of userClaims and discloseStructure do not match!")
                    )
                }
            }
    }

    @Test
    fun testCreateCredentialAsJson_jsonArray_ok() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("nicknames", setOf("Momo", "MadMax"))
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("nicknames", setOf<String>())
            )
        )

        val res = createCredential(
            userClaims = claims,
            issuerKey = issuerKey,
            discloseStructure = discloseStructure
        )

        assert(res.isNotEmpty())

    }

    @Test
    fun testCreateCredentialAsJson_jsonArray2_ok() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair(
                    "complexClaim", JSONArray(
                        setOf(
                            mapOf(
                                Pair("key1", "value1"),
                                Pair("key2", "value2")
                            ),
                            mapOf(
                                Pair("key3", "value3"),
                                Pair("key4", "value4")
                            ),
                            mapOf((Pair("Signature", "SigValue")))
                        )
                    )
                )
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair(
                    "complexClaim", JSONArray(
                        setOf(
                            JSONObject(mapOf<String, String>()),
                            JSONObject(mapOf<String, String>()),
                            JSONObject(
                                mapOf(
                                    Pair("Signature", "")
                                )
                            )
                        )
                    )
                )
            )
        )

        val res = createCredential(
            userClaims = claims,
            issuerKey = issuerKey,
            discloseStructure = discloseStructure
        )

        assert(res.isNotEmpty())

    }

    @Test
    fun testCreateSimpleCredentialAsJson_jsonArray_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("nicknames", "Momo"),
                Pair("cars", setOf("BMW", "Tesla", "Ford"))
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("nicknames", setOf<String>()),
                Pair("cars", ""),
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.contains("Structures of userClaims and discloseStructure do not match!")
            }
    }

    @Test
    fun testCreateSimpleCredentialAsJson_jsonArray2_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("nicknames", "Momo")
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("nicknames", setOf<String>())
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.contains("Structures of userClaims and discloseStructure do not match!")
            }
    }

    @Test
    fun testCreateSimpleCredentialAsJson_jsonArray3_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("nicknames", JSONObject(
                    mapOf(
                        Pair("name", "Momo")
                    )
                ))
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("nicknames", JSONArray(
                    listOf(
                        JSONObject(
                            mapOf(
                                Pair("name", "")
                            )
                        ),
                        JSONObject(
                            mapOf(
                                Pair("name", "")
                            )
                        )
                    )
                ))
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.contains("Structures of userClaims and discloseStructure do not match!")
            }
    }

    @Test
    fun testCreateSimpleCredentialAsJson_jsonArray4_ko() {
        val claims = JSONObject(
            mapOf(
                Pair("iss", "$issuer"),
                Pair("first_name", "Max"),
                Pair("last_name", "Muster"),
                Pair("age", "33"),
                Pair("nicknames", JSONArray(
                    listOf(
                        JSONArray(
                            listOf(
                                JSONObject(
                                    mapOf(
                                        Pair("name", "Mimo")
                                    )
                                )
                            )
                        ),
                        JSONObject(
                            mapOf(
                                Pair("name", "Momo")
                            )
                        )
                    )
                ))
            )
        )

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("nicknames", JSONArray(
                    listOf(
                        JSONObject(
                            mapOf(
                                Pair("name", "")
                            )
                        ),
                        JSONObject(
                            mapOf(
                                Pair("name", "")
                            )
                        )
                    )
                ))
            )
        )
        assertThrows<Exception> {
            createCredential(
                userClaims = claims,
                issuerKey = issuerKey,
                discloseStructure = discloseStructure
            )
        }
            .also {
                it.message?.contains("Structures of userClaims and discloseStructure do not match!")
            }
    }
}