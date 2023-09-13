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
import kotlin.test.*

internal class SdJwtKtTest {

    @Serializable
    private data class SimpleTestCredential(
        val iss: String,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val b: Boolean? = null,
        val age: Int? = null
    )

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

    @Test
    fun testSimpleCredentialWithNonceAud() {
        val testConfig = TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, null, "Simple Credential With Aud and Nonce")

        val claims = SimpleTestCredential(issuer,"Alice", "Wonderland", "alice@example.com", false, 21)
        val discloseStructure = SimpleTestCredential(iss = "")
        val releaseClaims = SimpleTestCredential(iss = "", givenName = "", email = "", age = 0)
        val expectedClaims = SimpleTestCredential(iss = issuer, givenName = "Alice", email = "alice@example.com", age = 21)

        val expectedClaimsKeys = listOf("given_name", "email", "age")

        testRoutine(expectedClaimsKeys, expectedClaims, claims, discloseStructure, releaseClaims, testConfig)
    }

    @Test
    fun testSimpleCredential() {
        val testConfig = TestConfig(trustedIssuers, issuerKey, issuer, null, null, null, "Simple Credential")

        val claims = SimpleTestCredential(issuer, "Alice", "Wonderland", "alice@example.com", false, 21)
        val discloseStructure = SimpleTestCredential(iss = "")
        val releaseClaims = SimpleTestCredential(iss = "", givenName = "", email = "", age = 0)
        val expectedClaims = SimpleTestCredential(iss = issuer, givenName = "Alice", email = "alice@example.com", age = 21)

        val expectedClaimsKeys = listOf("given_name", "email", "age")

        testRoutine(expectedClaimsKeys, expectedClaims, claims, discloseStructure, releaseClaims, testConfig)
    }

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
    fun testAdvancedCredential() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced Credential")

       val claims = IdCredential(
           issuer,
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val discloseStructure = IdCredential(iss = "")
        val releaseClaims = IdCredential(iss = "", givenName = "", familyName = "", nicknames = setOf(), address = Address())
        val expectedClaims = IdCredential(
            iss = issuer,
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val expectedClaimsKeys = listOf("given_name", "family_name", "nicknames", "address")

        testRoutine(expectedClaimsKeys, expectedClaims, claims, discloseStructure, releaseClaims, testConfig)
    }

    @Test
    fun testAdvancedCredentialStructured() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced Credential Structured")
        val claims = IdCredential(
            issuer,
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val discloseStructure = IdCredential(iss = "", address = Address())
        val releaseClaims = IdCredential(
            iss = "",
            givenName = "",
            familyName = "",
            nicknames = setOf(),
            address = Address(streetAddress = "", locality = "", zipCode = 0)
        )
        val expectedClaims = IdCredential(
            iss = issuer,
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address(streetAddress = "123 Main St", locality = "Anytown", zipCode = 123456)
        )

        val expectedClaimsKeys = listOf(
            "given_name",
            "family_name",
            "nicknames",
            "street_address",
            "locality",
            "zip_code"
        )

        testRoutine(
            expectedClaimsKeys,
            expectedClaims,
            claims,
            discloseStructure,
            releaseClaims,
            testConfig
        )
    }

    @Test
    fun noneHeader() {
        // eyJhbGciOiJub25lIn0. => {"alg":"none"}

        // None header in SD-JWT
        val noneHeaderSdJwtPresentation =
            "eyJhbGciOiJub25lIn0.eyJfc2QiOlsiU19wU3k4SHNPbTVvajJjWlkzMDV0X21lcTBtZ05Hb29mcVpIbUptN200ZyIsInczVnZ6NDBxeUExMG5WY2t1VUgtNjYwZ25DZXlqWHFWV25wckljQ3Q5cFkiLCJ4VE1URWttRkNyRk5YR1o0OHJkOTZobXdGY0ZJblVUTm82eWNYLUlxNEFrIiwiZFozWTJhcVBORE5xc21CWENiQVFWTnRGcHJMSnJ1VUlfYUtuOVdHWHd0QSIsIjZKdFBLdHQ0WW5CVm5LV3RjRlBpUE8xZFpLNS0xMTR0TWtjWDJyUWMzOUkiLCI0U1RVMzdpZ3loNVdPV3p1X2lBWkVaVHVWbkhxakI5Z2ZoWEpTeU1IUkFZIiwiYkhkeXJ4bjVjVTk4UHFGNjFaUU9qR2Q1ZXd2UzhKU3BXLVRHU0xmZS1aSSJdLCJhZGRyZXNzIjp7Il9zZCI6WyJwSEZ3UjRiQk1iTm53dWFQX1g4ekFzNHhzTmZxZHVIcWxRX25MNDRic01vIiwiSFlidElYNUpKeHpsMVpTQjB6YUtEam9ETHVmRG1MYXVnemF5RnZfa1NRbyIsIldrbzZTQl9QU2VDUHJWdjlidkl5dW5rUFdTc1NqTVd2N2FsUmcyZGFrRzgiLCJjdWJUOE9qbTduZzBXWDVVaDJCaWpUcjZNVkVYRDhCR3p0VEd6LUtOMGhvIiwiaWhORV9mcDRWMnRFSTllcmlEZGNmZmN1OUdIb2FicnBRYk04VDZSeFF2VSIsIkYtR3h4MTJnVTJfVl9vQXppUUFjd1BGVlgwNVJwa1VCamhMWVd4YzlZeFkiLCJ0YWxHOXEycktBdHI1UmVSWnpGSzBKSDdiMWVTY1pzTURmdjl5MVlwM2w0IiwiM0dyd0VZclZwSnJSc2NwTnJUZ0VoT0pZQnowOWE3U2Rwbk04Q1JRZUgzRSJdfSwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7Imp3ayI6eyJ4IjoiczZnVkxJTkxjQ0doR0VEVGZfdjF6TWx1TFpjWGo0R09YQWZRbE9XWk05USIsImt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJIb2xkZXJLZXkifX0sImV4cCI6MTY3NjM4NzcwOCwiaWF0IjoxNjc2MzAxMzA4fQ.rbdu6JOwbI1TseTVk8-HDRKHebLtliNK9-RoOCkykExL3VafDnbLFX0lSZmIX0fTtGNLU3HlG3cIXj2JBW4XCg~WyJ5bFlVRXRKeThBZy0xdVV5X0E1VzV3IiwiZmFtaWx5X25hbWUiLCJXb25kZXJsYW5kIl0~WyJ0elN0SGJncFFlaF8ydVZTWUlqc01nIiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~WyJwekdKS21QblgySzJLREV3XzF5ZlBnIiwibmlja25hbWVzIixbIkEiLCJCIl1d~WyI2RWlHSjkyUGh5bnJ4UmpybFAybGp3Iiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJ0cXV1OC04YXVvS0ZBWHpRenVfZlJ3IiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI2XzVkckp4R3JZb1pIejJMT01GVS13IiwiemlwX2NvZGUiLDEyMzQ1Nl0~eyJraWQiOiJIb2xkZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwOi8vdmVyaWZpZXIuZXhhbXBsZS5jb20iLCJub25jZSI6IjEyMzQ1IiwiaWF0IjoxNjc2MzAxMzA4fQ.AA1r68cEsVkJ12wSoDw5_SYDU9pR4PJbU2eKN_LzwsPkaIq9Ho8ScNcwK8W9C09wrWsIM8pGP7Y6Ntp-8R5iCQ"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderSdJwtPresentation, trustedIssuers, nonce, verifier, true)
        }

        // None header in holder binding JWT
        val noneHeaderHolderBindingPresentation = "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiV2FvT0tOV2VMQXhaYlVfbldTZzVXbWZZNTBHZHhwSmRtbHRfZkl2S3QtRSIsIkhoZ0RLZzAtbFU5dGJUdV9ORWxVZHZvWm53cU9mUnlZQ0wwMEZzajdTdWMiLCIwLWNRanVXZk5jZjNaVjJTT2lrYWVoWkozSEU1UXNNLTh5a0NncjUyb2MwIiwiV0N4WGQ3TmRadGRJb3FTU1owWEtJbEVZaUVrY1RkZ3VtRHpkcDNWc1c4dyIsIm1ldUhXcnZoNUxZYVZpbUc4SUxRZmtFaS1vTTVfMzZJQzZ6Z19QN19JV0kiLCIyTF9EcVpsZUhETS1oeks1eENtRy02MDRreEFnVDl0N3pUbmZ0Yk5TbTJzIiwiQmJsQXFBeG5qdmFMenFLR0hQRDd0cWJRUk5FQmFPYXNZZVF4VW41OGJhNCIsIkdaNmh6RnFwd25hZnhrQTMtTGs5dHVleE9PQ3d1TU1JWGVETEZrLVgyMFUiLCJRVklBdzIxUFRncnlIMU0yd0RINjZzeldULWZyRnU4WU5qNGJMSkpEa3ZVIiwiaFZ5RlNQR1FPSWhWeWpIT0c4YVNsTl9QbWlvNng5QVhydkRndUdwQmJSZyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6Imh0dHA6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJjbmYiOnsiandrIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9fSwiZXhwIjoxNjc2NDc5ODgyLCJpYXQiOjE2NzYzOTM0ODJ9.Zn09th3WkaQdyFim0OElUutofO-cohyH-dG-ElJGUq-YWSe71ONAoxh_9t3wNxMWihbdqlSMpcdje7QqDKMnAg~WyJGSDZUNTdPNXh0bnZQUjB4dTh6RHlRIiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~WyJCbzdaZm5XVVlkNkxxVm1mOE5iaEhnIiwiZmFtaWx5X25hbWUiLCJXb25kZXJsYW5kIl0~WyJhYVVQUWZoakxQU1V0eXBLLWZPLVFnIiwibmlja25hbWVzIixbIkEiLCJCIl1d~WyJ0anBKX0VaanM2dEEzWXR6UndweEF3IiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwiY291bnRyeSI6IlVTIiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJ6aXBfY29kZSI6MTIzNDU2fV0~eyJhbGciOiJub25lIn0.eyJhdWQiOiJodHRwOi8vdmVyaWZpZXIuZXhhbXBsZS5jb20iLCJub25jZSI6IjEyMzQ1IiwiaWF0IjoxNjc2MzkzNDgyfQ.KbPZidegP_0FpuNJgl0SZ0PPXGahQSszARPvOKxhj3jh4aejJOpWe3C9aYIyZtZI_Hk6Ks84ot1t30ylYjOWCg"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderHolderBindingPresentation, trustedIssuers, nonce, verifier, true)
        }
    }

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
                Pair("complexClaim", JSONArray(setOf(
                    mapOf(
                        Pair("key1", "value1"),
                        Pair("key2", "value2")),
                    mapOf(
                        Pair("key3", "value3"),
                        Pair("key4", "value4")),
                    mapOf((Pair("Signature", "SigValue")))
                ))
            )
        ))

        val discloseStructure = JSONObject(
            mapOf(
                Pair("iss", ""),
                Pair("first_name", ""),
                Pair("last_name", ""),
                Pair("age", ""),
                Pair("complexClaim", JSONArray(setOf(
                    JSONObject(mapOf<String, String>()),
                    JSONObject(mapOf<String, String>()),
                    JSONObject(mapOf(
                        Pair("Signature", "")
                    ))
                )))
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
                it.message?.let {
                    assert(
                        it.contains("Structures of userClaims and discloseStructure do not match!")
                    )
                }
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
                it.message?.let {
                    assert(
                        it.contains("Structures of userClaims and discloseStructure do not match!")
                    )
                }
            }
    }
}