package org.sd_jwt

import com.nimbusds.jose.jwk.RSAKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test

internal class AdvancedTest {

    private val verifier = "https://example.com/verifier"
    private val issuer = "https://example.com/issuer"

    private val issuerKeyJson = """
        {
            "d": "JQ5-MZ5wuwb8KBYiJqDbtCG3H9daEK-ITOnxWP7k7jcI4lotkO3vmMuCw_XJQKShUV6TpeI7AT_je1SY_7-ram2oM1xJcm0zoOUOvK62l7006bUB3BfHmYXEdEtr_-bzA_mMwpQsEztT_V0BNIFwX-oXnO9LXSTrgFcUTUnS_Vyp-0noziWQN4sx5YlBTniRIhAyU1eYqUDpqza2hmKJEpEYUR73h3OLUEQJblEY4-WR989MK4ff_GcJ7y1dV8YraTmsoOKs2qmelMdfO_SgZ5SjKNtl38yvr8hkEJpXgbBJV1bjzu2IOysxmxtrOjxHRjDHQEV2MAoYObJki33rzQ",
            "dp": "gDE4XKCd_TbQLH_buP3UDpgCSi3TmdaTfmiNyJHxrNqBTehsMYhEUDN2t84NEJKF-QXWaRP1IHb3T5MvDNrXZUf8vHQFh6BXcOceF2dC_PvGIX3K1Nwnb8T9u1VkwaN95h_hMoCk7E8mKw37cX4eeoRqtLsxBSFODbIhi4b9Yq0",
            "dq": "c26RA1V_1rX8sfrMMkCDADbb7tD55h8obuX2FMs2LhBs4T9vzwsm8dKZ1cl0VYui04hc-x6tAMwYFrz4Y0cGBcHQHgOL1ame_pQos1tCbOChBeczXVLlcKhwsvFCNjkM4jV05o8PHZ9Jk8dFbGJ_1RLTgaGLktFQgfkas8VjwKs",
            "e": "AQAB",
            "key_size": 2048,
            "kty": "RSA",
            "n": "6GwTTwcjVyOtKtuGf7ft5PAU0GiDtnD4DGcmtVrFQHVhtx05-DJigfmR-3Tetw-Od5su4TNZYzjh3tQ6Bj1HRdOfGmX9E9YbPw4goKg_d0kM4oZMUd64tmlAUFtX0NYaYnRkjQtok2CJBUq22wucK93JV11T38PYDATqbK9UFqMM3vu07XXlaQGXP1vh4iX04w4dU4d2xTACXho_wKKcV85yvIGrO1eGwwnSilTiqQbak31_VnHGNVVZEk4dnVO7eOc6MVZa-qPkVj77GaILO53TMq69Vp1faJoGFHjha_Ue5D8zfpiAEx2AsAeotIwNk2QT0UZkeZoK23Q-s4p1dQ",
            "p": "8_vXPiy3OtAeACYgNm6iIo5c1Cbwuh3tJ0T6lMcGEo7Rcro0nwNFISvPnFp_1Wl8I1ts6FTMsKyoTneveDrptlWSRRZNrFS_GyAQpG6GPUfqNh9n4T5J3mYw6-fLPM0hL0_EbDNiEXyL53ecMfi2xlg2T2opuZFeToogqipDudc",
            "q": "8953MqqJ7v-bc5rPQuRjqbHIxZJdEF-VsSz1lVbVEqnxV0XEUnM8yZqsXUe07V-5OEzJBqgrgLCcOeh5Jfs1MZI9tegRCwdw3uiqECAAVMtsM9xCwBY0mPu-oqOwaKsVOj2Slr1Gq-s67FdjGeMq6udjPWHgQ5QeOy78pgHtWZM",
            "qi": "FghQIPGfbjWmdwl5szDRPq1_NcGWSt9Eswu5o-JJq-jWUgTljqxufteg96k7pmBXMAQjGKn_lY41AojokVB4KWTJrPHF6z6oAm90kMLuFi80IbXzdb6TnsYHue_Y3Tbs4GtYP7YU9x2zrghsaUcDNJ7yH13h9F7GyiDkpySgcaM"
        }
    """.trimIndent()
    private val issuerKey = RSAKey.parse(issuerKeyJson)
    private val holderKeyJson = """
        {
            "d": "kJSUdxpBVUHSSe0HfJfeO3q-iDgjXlS9zEZmgifbUPtjcT8recXwmwwRTZzhb9avNy8tyL8i1dJooAeMnudECz4u5zRY6VIXnSkO2cSPhZ-fyXPpC1BAnzf8RSn8rGu_auRrfyq3dfYw6dLt7dzA-hsUANzD63x8Tt4v9eiwsp65BlR1pvf0BIV3WMGLtgx0hTUQBUxIx0hgDG439a0gLY0T86m9LEMCcVXONNTWbScQf5KsHLWQgbjCeUc_4szy4RwsaFnF40uut_fdZyM_O1pOsfYJLa8fmN3FC72l4UdJvtFXWuH-20ywTEOKISF7CRx5BsifOnyEMTeAVEE9wQ",
            "dp": "kqCTyxU7gJa3gY4tn9OABui7por98yRlQUl7HYo63nPYPhCK3zMFcEOL8xjYot1cYYCGxE5yFxqkbX9fmbWEsRmx_BsgRPdraZ5DhvCES3BYstJAVctS-2LikGMK7veV7r6tEoKPvmKrkOKH90_-0GVvdG0GJn7Ccqz9OTWa1sE",
            "dq": "DYqOZnhR_1GZhNaMyVdAOcLt3Sw20TL90pEPSbYLGtcBLqZkyo9wNtMguYd_YFXHojF_iNwQW9IdYE7hVgA87tLEgM8S-1zQFVI2jGkBbqHisncQ4NdbEdIXxc3YHyCQmurPPW_EjKhyRKzHoalkJoUUSWF0S34MXoiFHIEae-s",
            "e": "AQAB",
            "key_size": 2048,
            "kty": "RSA",
            "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
            "p": "0AZrdzBIpxDQggVh0x4GYBmNDuC8Ut_qOAKNLbpJLaWHFmeMjQRnXM8nxZfmhzAQ10XAS6n7TyFqK-PrhfmKWZ0g34UVfeXd4-D-gqegIDZ3TNwNCOBLOpwdDrHeB06ZdJ1o2OI1XLTO12PQN6PRUVKKF0dFdXV7NAM8YpJkxmE",
            "q": "zM_2m4uE2ldfNMOJmCMRm2S2NpiMOYi3Pp6Q6c4QtpF1up0Bak0Whox4F6VN6ydJjgolXFITufUU4XhT8p9WvDdCrY5u3NWbGMXMC426JPHXBKdHqQvAf3LFcbWNjrjowBktkPyDbB5sL3H8ey-q6tzGqLirZGZSKFiZ6J3OUFM",
            "qi": "O7leKcjIonKzTlI2EcShf4Vdlw-AvlQqAHmpGttHP0Vr--R4RteORtdXGUZC92GNaiHmkDLwak8ENfewKUP9xMyE_Psc5N090P_y9yKaIQnqN5QYe7quisqYtD64xP-568JaQCCqUtrVFT62jFhl0cVQ8Fy2oqdaKBufjLv-ssc"
        }
    """.trimIndent()
    private val holderKey = RSAKey.parse(holderKeyJson)

    private val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

    private val nonce = "yoxCiDm5sVP-OTNYta_DDg"

    @Serializable
    private data class Address(
        @SerialName("street_address") val streetAddress: String? = null,
        val locality: String? = null,
        val region: String? = null,
        val country: String? = null
    )

    @Serializable
    private data class SimpleCredential(
        val iss: String,
        val sub: String? = null,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        @SerialName("phone_number") val phoneNumber: String? = null,
        val address: Address? = null,
        val birthdate: String? = null
    )

    @Test
    internal fun simpleTest() {
        val testConfig = TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Simple Test")
        val claims = SimpleCredential(
            issuer,
            "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "John",
            "Doe",
            "johndoe@example.com",
            "+1-202-555-0101",
            Address("123 Main St", "Anytown", "Anystate", "US"),
            "1940-01-01"
        )
        val discloseStructure = SimpleCredential(iss = "")
        val releaseClaims = SimpleCredential(iss = "", givenName = "", familyName = "", address = Address())
        val expectedClaims = SimpleCredential(
            iss = issuer,
            givenName = "John",
            familyName = "Doe",
            address = Address(streetAddress = "123 Main St", locality = "Anytown", region = "Anystate", country = "US")
        )

        val expectedClaimsKeys = listOf("given_name", "family_name", "address")

        testRoutine(expectedClaimsKeys, expectedClaims, claims, discloseStructure, releaseClaims, testConfig)
    }

    @Test
    internal fun simpleStructuredTest() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Simple Structured Test")
        val claims = SimpleCredential(
            issuer,
            "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "John",
            "Doe",
            "johndoe@example.com",
            "+1-202-555-0101",
            Address("123 Main St", "Anytown", "Anystate", "US"),
            "1940-01-01"
        )
        val discloseStructure = SimpleCredential(iss = "", address = Address())
        val releaseClaims = SimpleCredential(
            iss = "",
            givenName = "",
            familyName = "",
            address = Address(region = "", country = ""),
            birthdate = ""
        )
        val expectedClaims = SimpleCredential(
            iss = issuer,
            givenName = "John",
            familyName = "Doe",
            birthdate = "1940-01-01",
            address = Address(region = "Anystate", country = "US")
        )

        val expectedClaimsKeys = listOf("given_name", "family_name", "birthdate", "region", "country")

        testRoutine(
            expectedClaimsKeys,
            expectedClaims,
            claims,
            discloseStructure,
            releaseClaims,
            testConfig
        )
    }

    @Serializable
    private data class Issuer(
        val name: String? = null,
        val country: String? = null
    )

    @Serializable
    private data class Document(
        val type: String? = null,
        val issuer: Issuer? = null,
        val number: String? = null,
        @SerialName("date_of_issuance") val dateOfIssuance: String? = null,
        @SerialName("date_of_expiry") val dataOfExpiry: String? = null
    )

    @Serializable
    private data class Evidence(
        val type: String? = null,
        val method: String? = null,
        val time: String? = null,
        val document: Document? = null
    )

    @Serializable
    private data class PlaceOfBirth(
        val country: String? = null,
        val locality: String? = null
    )

    @Serializable
    private data class AddressComplex(
        val locality: String? = null,
        @SerialName("postal_code") val postalCode: String? = null,
        val country: String? = null,
        @SerialName("street_address") val streetAddress: String? = null
    )

    @Serializable
    private data class Claims(
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val birthdate: String? = null,
        @SerialName("place_of_birth") val placeOfBirth: PlaceOfBirth? = null,
        val nationalities: Set<String>? = null,
        val address: AddressComplex? = null
    )

    @Serializable
    private data class Verification(
        @SerialName("trust_framework") val trustFramwork: String? = null,
        val time: String? = null,
        @SerialName("verification_process") val verificationProcess: String? = null,
        val evidence: Set<Evidence>? = null
    )

    @Serializable
    private data class VerifiedClaims(
        val verification: Verification? = null,
        val claims: Claims? = null
    )

    @Serializable
    private data class ComplexCredential(
        val iss: String,
        @SerialName("verified_claims") val verifiedClaims: VerifiedClaims? = null,
        @SerialName("birth_middle_name") val birthMiddleName: String? = null,
        val salutation: String? = null,
        val msisdn: String? = null
    )

    @Test
    internal fun complexTest() {
        val testConfig = TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Complex Test")
        val claims = ComplexCredential(
            iss = issuer,
            verifiedClaims = VerifiedClaims(
                verification = Verification(
                    trustFramwork = "de_aml",
                    time = "2012-04-23T18:25Z",
                    verificationProcess = "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                    evidence = setOf(
                        Evidence(
                            type = "document",
                            method = "pipp",
                            time = "2012-04-22T11:30Z",
                            document = Document(
                                type = "idcard",
                                issuer = Issuer(name = "Stadt Augsburg", country = "DE"),
                                number = "53554554",
                                dateOfIssuance = "2010-03-23",
                                dataOfExpiry = "2020-03-22"
                            )
                        )
                    ),
                ),
                claims = Claims(
                    givenName = "Max",
                    familyName = "Meier",
                    birthdate = "1956-01-28",
                    placeOfBirth = PlaceOfBirth(country = "DE", locality = "Musterstadt"),
                    nationalities = setOf("DE"),
                    address = AddressComplex(
                        locality = "Maxstadt",
                        postalCode = "12344",
                        country = "DE",
                        streetAddress = "An der Weide 22"
                    )
                )
            ),
            birthMiddleName = "Timotheus",
            salutation = "Dr.",
            msisdn = "49123456789"
        )
        val discloseStructure = ComplexCredential(
            iss = "",
            verifiedClaims = VerifiedClaims(
                verification = Verification(evidence = setOf(Evidence(document = Document(issuer = Issuer())))),
                claims = Claims(placeOfBirth = PlaceOfBirth())
            )
        )
        val releaseClaims = ComplexCredential(
            iss = "",
            verifiedClaims = VerifiedClaims(
                verification = Verification(trustFramwork = "", time = "", evidence = setOf(Evidence(type = ""))),
                claims = Claims(
                    givenName = "",
                    familyName = "",
                    birthdate = "",
                    placeOfBirth = PlaceOfBirth(country = "")
                )
            )
        )
        val expectedClaims = ComplexCredential(
            iss = issuer,
            VerifiedClaims(
                verification = Verification(
                    trustFramwork = "de_aml",
                    time = "2012-04-23T18:25Z",
                    evidence = setOf(Evidence(type = "document", document = Document(issuer = Issuer())))
                ),
                claims = Claims(
                    givenName = "Max",
                    familyName = "Meier",
                    birthdate = "1956-01-28",
                    placeOfBirth = PlaceOfBirth(country = "DE")
                )
            )
        )

        val expectedClaimsKeys = listOf("trust_framework", "time", "type", "given_name", "family_name", "birthdate", "country")

        testRoutine(
            expectedClaimsKeys,
            expectedClaims,
            claims,
            discloseStructure,
            releaseClaims,
            testConfig
        )
    }
}
