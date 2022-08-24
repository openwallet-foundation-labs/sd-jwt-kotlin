package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.*

internal class SdJwtKtTest {

    @Serializable
    private data class SimpleTestCredential(
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val b: Boolean? = null,
        val age: Int? = null
    )

    private val verifier = "http://verifier.example.com"
    private val issuer = "http://issuer.example.com"

    private val issuerKeyJson = """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
    private val issuerKey = OctetKeyPair.parse(issuerKeyJson)
    private val holderKeyJson = """{"kty":"OKP","d":"8G6whDz1owU1k7-TqtP3xEMasdI3t3j2AvpvXVwwrHQ","crv":"Ed25519","kid":"HolderKey","x":"s6gVLINLcCGhGEDTf_v1zMluLZcXj4GOXAfQlOWZM9Q"}"""
    private val holderKey = OctetKeyPair.parse(holderKeyJson)
    private val holderPublicKey = holderKey.toPublicJWK()

    private val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

    @Test
    fun testSimpleCredential() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims0 = SimpleTestCredential("Alice", "Wonderland", "alice@example.com", false, 21)
        println("Claims for credential0: $claims0\n")

        val credential0 = createCredential(claims0, null, issuer, issuerKey)
        println("Credential0: $credential0\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims0 = SimpleTestCredential(givenName = "",  email = "", age = 0)
        val presentation0 = createPresentation(credential0, releaseClaims0, verifier, "12345", null)
        println("Presentation0: $presentation0\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedSimpleTestCredential = verifyPresentation<SimpleTestCredential>(presentation0, trustedIssuers,"12345", verifier)
        println("Verified Login Credential: $verifiedSimpleTestCredential\n")

        // End-to-End tests
        val simpleCredential = SimpleTestCredential(givenName = "Alice", email = "alice@example.com", age = 21)
        assertEquals(simpleCredential, verifiedSimpleTestCredential)
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
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val birthday: String? = null,
        val nicknames: Set<String>? = null,
        val address: Address? = null
    )

    @Test
    fun testAdvancedCredential0() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims1 = IdCredential(
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        println("Claims for credential1: $claims1\n")

        val credential1 = createCredential(claims1, holderPublicKey, issuer, issuerKey)
        println("Credential1: $credential1\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims1 = IdCredential(givenName = "", familyName = "", nicknames = setOf(), address = Address())
        val presentation1 = createPresentation(credential1, releaseClaims1, verifier, "12345", holderKey)
        println("Presentation1: $presentation1\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, trustedIssuers,"12345", verifier)
        println("Verified Id Credential: $verifiedIdCredential")

        // End-to-End tests
        val idCredential = IdCredential(
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        assertEquals(idCredential, verifiedIdCredential)
    }

    @Test
    fun testAdvancedCredential1() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims1 = IdCredential(
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val discloseStructure = IdCredential(address = Address())
        println("Claims for credential1: $claims1\n")

        val credential1 = createCredential(claims1, holderPublicKey, issuer, issuerKey, discloseStructure)
        println("Credential1: $credential1\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims1 = IdCredential(givenName = "", familyName = "", nicknames = setOf(), address = Address(streetAddress = "", locality = "", zipCode = 0))
        val presentation1 = createPresentation(credential1, releaseClaims1, verifier, "12345", holderKey)
        println("Presentation1: $presentation1\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, trustedIssuers,"12345", verifier)
        println("Verified Id Credential: $verifiedIdCredential")

        // End-to-End tests
        val idCredential = IdCredential(
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address(streetAddress = "123 Main St", locality = "Anytown", zipCode = 123456)
        )
        assertEquals(idCredential, verifiedIdCredential)
    }

    @Test
    fun noneHeader() {
        // eyJhbGciOiAibm9uZSJ9. => {"alg": "none"}
        val noneHeaderPresentation = "eyJhbGciOiAibm9uZSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjEwMzg3NzEsImlhdCI6MTY2MDk1MjM3MSwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6ImVjeWc1SGEzRVA4ZHloSXhXRXJJNFVVVUJtbEZFXzU4UFBHbnVJWThDaVkiLCJhZGRyZXNzIjoiYUFjZUlzN0lDTDk0c0d0UUtqLVZ3b04tLXo0R1lXcUNvNHdFOW1XOUlGUSIsIm5pY2tuYW1lcyI6Il9wckJJeS1RZ2VpMXFFRHVpcDRtSlJRTmQ0U1BjRVRMUWZPRlBaMW9fRTAiLCJnaXZlbl9uYW1lIjoieFlzQUpSOGtockJtUEhIYUtWOVRibXl4VTN4NEdJVUZOMm5wR3g5aHYwUSIsImZhbWlseV9uYW1lIjoiSGR0MWJMdWZsMXk3d1JPUkFGM2p1czBXWTNXLVFZdnRIR3RhWVpKNUl1SSIsImVtYWlsIjoiUVpvaEtmUzFqdFJuZFVJakFndi0tdGxPUnQ2dFhuM3U5YWFfeG8tNWxuWSJ9fQ.e5ygxCyVZZe1kt1S1bcK383EYZn3GebiQ0aL9a_hqSFQbxei408OQUnRtYCQFDIxHtE24eY6RteUtAWZTwi0AA.eyJhbGciOiAibm9uZSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOiJbXCJwU3ZBZFZzS09VUkJnaGFyRlprXzV3XCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJwcFNwdXo1d0tmY2ZYZ1pfV2RPYmxRXCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wiV3dtZ3BiTzVvNTJiWnhjMjJJYmV0Z1wiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcImdGYldfR2ZjbFdId3ppYnNWQU93SXdcIixcIldvbmRlcmxhbmRcIl0ifSwiYXVkIjoiaHR0cDovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwibm9uY2UiOiIxMjM0NSJ9.POOBnye2FDNE2YLhvmy-knlE1CX3vN2VA5uEebHB4WxEt5PhDCPRJAVh2WG97rfLvA8JCuYZXpD7ACeV-MuKCA"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderPresentation, trustedIssuers, "12345", verifier)
        }

        val noneHeaderSDJWTRPresentation = "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjEwNDE1MjQsImlhdCI6MTY2MDk1NTEyNCwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6Ik81eTd4TFA3SUFia0J5RlVSZW5zZ3dXa0JNd1AxRVN5ZHBZUDFJTnVBQlEiLCJhZGRyZXNzIjoiODY3d2t5WVExZFM1S1N4aUZZOEFpcmZWMkQyc29UUXpVbXBVZWg3c25tbyIsIm5pY2tuYW1lcyI6IkwxTEpTVWJxTk1aMnJRdkdSdF9EWUFybU1DNld5SHF0bEpUWmM1ZWcxdmciLCJnaXZlbl9uYW1lIjoiMU84X29nQ1NiRzNxWm1NU0FPbUN4a1pzc0FMcjh1N09ad3h0czl1eWdsayIsImZhbWlseV9uYW1lIjoiZWlxbEp5UHNNdUdYeUc3OUo3cFNkNkcxWUdYdF9LdXFWeEstaG9GejJkUSIsImVtYWlsIjoiWFlUNWowMWtudVJqcG0ycnpzMktldThVQnNuWE1LeGxiZmxxSEFDR0pWZyJ9fQ.qUPdx5eU3P_0mMudJ3SNPpckTklUzFyMz5a3mhu59k6NaUNLC22znYprZSX-9rUKXeL5rKudmBCm2LjmL_YwDQ.eyJhbGciOiAibm9uZSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOiJbXCJHS1pZNDU3MF8yalZtZnhHUXR3WUNBXCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJ1blRRVlVfb2NhdzdyazUxaFFkSkZ3XCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wieGJvZy1kekN6ZGwxMWJwdE1udjlEUVwiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcImtEVTh2MVpPTjRxRTh5MnZDekJuMmdcIixcIldvbmRlcmxhbmRcIl0ifSwiYXVkIjoiaHR0cDovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwibm9uY2UiOiIxMjM0NSJ9.csQ42IpP6Wjk6A0Yobn6HoV7ADfW-5365BKMLbtWQVh3WyEvWMGKXpE3xcB1k3NijekYLcX_oSMKXMIuc8-YCA"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderSDJWTRPresentation, trustedIssuers, "12345", verifier)
        }
    }
}