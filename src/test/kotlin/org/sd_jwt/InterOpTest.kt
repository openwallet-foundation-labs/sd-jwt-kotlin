package org.sd_jwt

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

internal class InterOpTest {

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
    private val holderPublicKey = holderKey.toPublicJWK()

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
        val sub: String? = null,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        @SerialName("phone_number") val phoneNumber: String? = null,
        val address: Address? = null,
        val birthdate: String? = null
    )

    private fun splitPresentation(presentation: String): Pair<String, SignedJWT> {
        val split = presentation.split(".")
        val sdJwt = "${split[0]}.${split[1]}.${split[2]}"
        val sdJwtR = "${split[3]}.${split[4]}.${split[5]}"
        return Pair(sdJwt, SignedJWT.parse(sdJwtR))
    }

    @Test
    internal fun simpleTest() {
        println("=========================================")
        println("============== Simple Test ==============")
        println("=========================================")
        // Create credential
        val claims = SimpleCredential(
            "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "John",
            "Doe",
            "johndoe@example.com",
            "+1-202-555-0101",
            Address("123 Main St", "Anytown", "Anystate", "US"),
            "1940-01-01"
        )
        val credentialGen = createCredential(claims, holderPublicKey, issuer, issuerKey)
        println("Credential: $credentialGen")

        // Compare presentations
        val credential = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxMjE1OSwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InN1YiI6ICJ6NHhnRWNvOTRkaVRhU3J1SVNQaUU3b193dG1jT2ZuSF84UjdYOVBhNTc4IiwgImdpdmVuX25hbWUiOiAiUHZVN2NXanVIVXE2dy1pOVhGcFFaaGpULXVwclFMM0dIM21Lc0FKbDBlMCIsICJmYW1pbHlfbmFtZSI6ICJILVJlbHI0Y0VCTWxlbnlLMWd2eXgxNlFWcG50NE1FY2xUNXRQMGFUTEZVIiwgImVtYWlsIjogIkVUMkExSlFMRjg1WnBCdWxoNlVGc3RHclNmUjRCM0tNLWJqUVZsbGh4cVkiLCAicGhvbmVfbnVtYmVyIjogIlNKbmNpQjJESVJWQTVjWEJyZEtvSDZuNDU3ODhtWnlVbjJybnY3NHVNVlUiLCAiYWRkcmVzcyI6ICIwRmxkcUxmR25FUlBQVkRDMTdvZDl4YjR3M2lSSlRFUWJXX1lrOUFtbkR3IiwgImJpcnRoZGF0ZSI6ICItTDBrTWdJYkxYZTNPRWtLVFVHd3pfUUtoamVoRGVvZktHd29QcnhMdW80In19.v_YCkMrzEtIip7z0fufeNVJmAfoiJSezvcvfBUtXMNGrNRLzQvRtFbj7qEKXAPD8QlJdh5SWVrubuKbn6sWQfH0SOj2pvUPYbziCZ1D8UmF29B9EjQVSbsphr2VoqyHZruQPI1RC-f5Dpj25WmvYLFoR76l3xRzqODeO08rkoGjkmHZseM5WVMdP0nIm5WR9Jc0Qv2W4-8vWgZV4b6fyrFf2TUbPwbSTmEWOYVayq5vMXnouPCpDPUjOPymybm6TL7Ub56MaHCc4kLcvyOJPeEebyvuO_uIV4YoUsbLsSVLKSqIaeB3QggL8O1ysZPN1B_geao0HsjJ1yZIG3Uc_OQ.eyJzZF9yZWxlYXNlIjogeyJzdWIiOiAiW1wiMkdMQzQyc0tRdmVDZkdmcnlOUk45d1wiLCBcIjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyY1wiXSIsICJnaXZlbl9uYW1lIjogIltcImVsdVY1T2czZ1NOSUk4RVluc3hBX0FcIiwgXCJKb2huXCJdIiwgImZhbWlseV9uYW1lIjogIltcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcIiwgXCJEb2VcIl0iLCAiZW1haWwiOiAiW1wiZUk4WldtOVFuS1BwTlBlTmVuSGRoUVwiLCBcImpvaG5kb2VAZXhhbXBsZS5jb21cIl0iLCAicGhvbmVfbnVtYmVyIjogIltcIlFnX082NHpxQXhlNDEyYTEwOGlyb0FcIiwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLCAiYWRkcmVzcyI6ICJbXCJBSngtMDk1VlBycFR0TjRRTU9xUk9BXCIsIHtcInN0cmVldF9hZGRyZXNzXCI6IFwiMTIzIE1haW4gU3RcIiwgXCJsb2NhbGl0eVwiOiBcIkFueXRvd25cIiwgXCJyZWdpb25cIjogXCJBbnlzdGF0ZVwiLCBcImNvdW50cnlcIjogXCJVU1wifV0iLCAiYmlydGhkYXRlIjogIltcIlBjMzNKTTJMY2hjVV9sSGdndl91ZlFcIiwgXCIxOTQwLTAxLTAxXCJdIn19"
        val presentation = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxMjE1OSwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InN1YiI6ICJ6NHhnRWNvOTRkaVRhU3J1SVNQaUU3b193dG1jT2ZuSF84UjdYOVBhNTc4IiwgImdpdmVuX25hbWUiOiAiUHZVN2NXanVIVXE2dy1pOVhGcFFaaGpULXVwclFMM0dIM21Lc0FKbDBlMCIsICJmYW1pbHlfbmFtZSI6ICJILVJlbHI0Y0VCTWxlbnlLMWd2eXgxNlFWcG50NE1FY2xUNXRQMGFUTEZVIiwgImVtYWlsIjogIkVUMkExSlFMRjg1WnBCdWxoNlVGc3RHclNmUjRCM0tNLWJqUVZsbGh4cVkiLCAicGhvbmVfbnVtYmVyIjogIlNKbmNpQjJESVJWQTVjWEJyZEtvSDZuNDU3ODhtWnlVbjJybnY3NHVNVlUiLCAiYWRkcmVzcyI6ICIwRmxkcUxmR25FUlBQVkRDMTdvZDl4YjR3M2lSSlRFUWJXX1lrOUFtbkR3IiwgImJpcnRoZGF0ZSI6ICItTDBrTWdJYkxYZTNPRWtLVFVHd3pfUUtoamVoRGVvZktHd29QcnhMdW80In19.v_YCkMrzEtIip7z0fufeNVJmAfoiJSezvcvfBUtXMNGrNRLzQvRtFbj7qEKXAPD8QlJdh5SWVrubuKbn6sWQfH0SOj2pvUPYbziCZ1D8UmF29B9EjQVSbsphr2VoqyHZruQPI1RC-f5Dpj25WmvYLFoR76l3xRzqODeO08rkoGjkmHZseM5WVMdP0nIm5WR9Jc0Qv2W4-8vWgZV4b6fyrFf2TUbPwbSTmEWOYVayq5vMXnouPCpDPUjOPymybm6TL7Ub56MaHCc4kLcvyOJPeEebyvuO_uIV4YoUsbLsSVLKSqIaeB3QggL8O1ysZPN1B_geao0HsjJ1yZIG3Uc_OQ.eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZExZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJ5b3hDaURtNXNWUC1PVE5ZdGFfRERnIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVhc2UiOiB7ImdpdmVuX25hbWUiOiAiW1wiZWx1VjVPZzNnU05JSThFWW5zeEFfQVwiLCBcIkpvaG5cIl0iLCAiZmFtaWx5X25hbWUiOiAiW1wiNklqN3RNLWE1aVZQR2JvUzV0bXZWQVwiLCBcIkRvZVwiXSIsICJhZGRyZXNzIjogIltcIkFKeC0wOTVWUHJwVHRONFFNT3FST0FcIiwge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSJ9fQ.bDLWxvCQeuW51lQUbWdRkLsVCvokvMaUwvDow1jL-nchuk1MYBDezcIPtpDqWWKnlSi9HWWOT8vKLWUfej3uZJNU825sVQwTMgp8rqvGAdfGEEdmP1FrsVt9f3-nXloCBAlCS3O1klyxXPQBmX-M2wB0oGfQczTC8cA4xU3McWpK1qgHZCS8i7t2XalNoxKfJy1dQrGvDBNwt52TDeyLG8fzdOEjT9O3L0AX91UumCGZGc8FuVIu5ibEPvLTxiLfr4L6du79V_kTXDprOsOWue_ohqt91PQnVGOXidyZWXpd9IT3IRE0PZFzW3MmwtxS6uvIGUSw2x5iMyiEwhhXLQ"

        val releaseClaims = SimpleCredential(givenName = "", familyName = "", address = Address())
        val presentationGen = createPresentation(credential, releaseClaims, verifier, nonce, holderKey)

        val (sdJwtGen, sdJwtRGen) = splitPresentation(presentationGen)
        val (sdJwt, sdJwtR) = splitPresentation(presentation)
        assertEquals(sdJwt, sdJwtGen)
        assertEquals(sdJwtR.jwtClaimsSet, sdJwtRGen.jwtClaimsSet)

        // Verify
        val verifiedSimpleCredential = verifyPresentation<SimpleCredential>(presentation, trustedIssuers, nonce, verifier)

        println("Verified credential: $verifiedSimpleCredential")

        val simpleCredential = SimpleCredential(
            givenName = "John",
            familyName = "Doe",
            address = Address(streetAddress = "123 Main St", locality = "Anytown", region = "Anystate", country = "US")
        )
        assertEquals(simpleCredential, verifiedSimpleCredential)
    }

    @Test
    internal fun simpleStructuredTest() {
        println("==========================================")
        println("========= Simple Structured Test =========")
        println("==========================================")
        // Create credential
        val claims = SimpleCredential(
            "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "John",
            "Doe",
            "johndoe@example.com",
            "+1-202-555-0101",
            Address("123 Main St", "Anytown", "Anystate", "US"),
            "1940-01-01"
        )
        val credentialGen = createCredential(claims, holderPublicKey, issuer, issuerKey, 2)
        println("Credential: $credentialGen")

        // Compare presentations
        val credential = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxNTI3MSwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InN1YiI6ICJ6NHhnRWNvOTRkaVRhU3J1SVNQaUU3b193dG1jT2ZuSF84UjdYOVBhNTc4IiwgImdpdmVuX25hbWUiOiAiUHZVN2NXanVIVXE2dy1pOVhGcFFaaGpULXVwclFMM0dIM21Lc0FKbDBlMCIsICJmYW1pbHlfbmFtZSI6ICJILVJlbHI0Y0VCTWxlbnlLMWd2eXgxNlFWcG50NE1FY2xUNXRQMGFUTEZVIiwgImVtYWlsIjogIkVUMkExSlFMRjg1WnBCdWxoNlVGc3RHclNmUjRCM0tNLWJqUVZsbGh4cVkiLCAicGhvbmVfbnVtYmVyIjogIlNKbmNpQjJESVJWQTVjWEJyZEtvSDZuNDU3ODhtWnlVbjJybnY3NHVNVlUiLCAiYWRkcmVzcyI6IHsic3RyZWV0X2FkZHJlc3MiOiAiTzdfSXNkNkNtWnFjU29iUFZwTWdtSndCNDFoUFVISEc4amc1TEo4WXpmWSIsICJsb2NhbGl0eSI6ICJ3LXpURjZsamtRTFR2VnlwX0pOeUQzdDVXYWotQjJ2YjBBWEgxcThPc2pJIiwgInJlZ2lvbiI6ICJuVHZvS3BHQTZZUXdFWmlwVkJJTTRXVkg5S1dFbndpcXNSakVocnhoUXo0IiwgImNvdW50cnkiOiAidS1PMXlEUXFEVFRxT2dVQlNqV2lsZ2tNTHpnX1FPVEVMTWZaclJUNWU2ayJ9LCAiYmlydGhkYXRlIjogIlRpcHlveEQ0M1BaSkY4WkVtS1ByYnhNRWxwRlhfTTdhQkxrVXBDLVc1M28ifX0.2BvyPIKjifFJIRWKuF_9U8PuWQDWMuQjjYMGYaWcbKMb887ZjraVkIMd-Nf8SKdNDIEJwpKgpFtIy2uc_si83dI2b2MP3Hxw8tz6rC7tzjjZvZYd9975bkT1445QPPKB9T_Vf2nkWgvy2GinaF1_BCdo_0REURGtKqNTw8LHhPeYIFr7JHa3i-SXOd7CgxA_9FNyjsgdanwH1thLGVRBK5nmag0N36ZmSBnCnp9fY4lUQzNBPfmEmhMNIrh329wpbB1T4WiHChE1wbKk_HQr9Yk6bENy6-ZOdNkNMufDzyUPPd6JBwLxZ2TUC5bJPIaIR5tR3tY8rutTpkIa5fDO3w.eyJzZF9yZWxlYXNlIjogeyJzdWIiOiAiW1wiMkdMQzQyc0tRdmVDZkdmcnlOUk45d1wiLCBcIjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyY1wiXSIsICJnaXZlbl9uYW1lIjogIltcImVsdVY1T2czZ1NOSUk4RVluc3hBX0FcIiwgXCJKb2huXCJdIiwgImZhbWlseV9uYW1lIjogIltcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcIiwgXCJEb2VcIl0iLCAiZW1haWwiOiAiW1wiZUk4WldtOVFuS1BwTlBlTmVuSGRoUVwiLCBcImpvaG5kb2VAZXhhbXBsZS5jb21cIl0iLCAicGhvbmVfbnVtYmVyIjogIltcIlFnX082NHpxQXhlNDEyYTEwOGlyb0FcIiwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLCAiYWRkcmVzcyI6IHsic3RyZWV0X2FkZHJlc3MiOiAiW1wiQUp4LTA5NVZQcnBUdE40UU1PcVJPQVwiLCBcIjEyMyBNYWluIFN0XCJdIiwgImxvY2FsaXR5IjogIltcIlBjMzNKTTJMY2hjVV9sSGdndl91ZlFcIiwgXCJBbnl0b3duXCJdIiwgInJlZ2lvbiI6ICJbXCJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBXCIsIFwiQW55c3RhdGVcIl0iLCAiY291bnRyeSI6ICJbXCJsa2x4RjVqTVlsR1RQVW92TU5JdkNBXCIsIFwiVVNcIl0ifSwgImJpcnRoZGF0ZSI6ICJbXCJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBXCIsIFwiMTk0MC0wMS0wMVwiXSJ9fQ"
        val presentation = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxNTI3MSwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InN1YiI6ICJ6NHhnRWNvOTRkaVRhU3J1SVNQaUU3b193dG1jT2ZuSF84UjdYOVBhNTc4IiwgImdpdmVuX25hbWUiOiAiUHZVN2NXanVIVXE2dy1pOVhGcFFaaGpULXVwclFMM0dIM21Lc0FKbDBlMCIsICJmYW1pbHlfbmFtZSI6ICJILVJlbHI0Y0VCTWxlbnlLMWd2eXgxNlFWcG50NE1FY2xUNXRQMGFUTEZVIiwgImVtYWlsIjogIkVUMkExSlFMRjg1WnBCdWxoNlVGc3RHclNmUjRCM0tNLWJqUVZsbGh4cVkiLCAicGhvbmVfbnVtYmVyIjogIlNKbmNpQjJESVJWQTVjWEJyZEtvSDZuNDU3ODhtWnlVbjJybnY3NHVNVlUiLCAiYWRkcmVzcyI6IHsic3RyZWV0X2FkZHJlc3MiOiAiTzdfSXNkNkNtWnFjU29iUFZwTWdtSndCNDFoUFVISEc4amc1TEo4WXpmWSIsICJsb2NhbGl0eSI6ICJ3LXpURjZsamtRTFR2VnlwX0pOeUQzdDVXYWotQjJ2YjBBWEgxcThPc2pJIiwgInJlZ2lvbiI6ICJuVHZvS3BHQTZZUXdFWmlwVkJJTTRXVkg5S1dFbndpcXNSakVocnhoUXo0IiwgImNvdW50cnkiOiAidS1PMXlEUXFEVFRxT2dVQlNqV2lsZ2tNTHpnX1FPVEVMTWZaclJUNWU2ayJ9LCAiYmlydGhkYXRlIjogIlRpcHlveEQ0M1BaSkY4WkVtS1ByYnhNRWxwRlhfTTdhQkxrVXBDLVc1M28ifX0.2BvyPIKjifFJIRWKuF_9U8PuWQDWMuQjjYMGYaWcbKMb887ZjraVkIMd-Nf8SKdNDIEJwpKgpFtIy2uc_si83dI2b2MP3Hxw8tz6rC7tzjjZvZYd9975bkT1445QPPKB9T_Vf2nkWgvy2GinaF1_BCdo_0REURGtKqNTw8LHhPeYIFr7JHa3i-SXOd7CgxA_9FNyjsgdanwH1thLGVRBK5nmag0N36ZmSBnCnp9fY4lUQzNBPfmEmhMNIrh329wpbB1T4WiHChE1wbKk_HQr9Yk6bENy6-ZOdNkNMufDzyUPPd6JBwLxZ2TUC5bJPIaIR5tR3tY8rutTpkIa5fDO3w.eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZExZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJ5b3hDaURtNXNWUC1PVE5ZdGFfRERnIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVhc2UiOiB7ImdpdmVuX25hbWUiOiAiW1wiZWx1VjVPZzNnU05JSThFWW5zeEFfQVwiLCBcIkpvaG5cIl0iLCAiZmFtaWx5X25hbWUiOiAiW1wiNklqN3RNLWE1aVZQR2JvUzV0bXZWQVwiLCBcIkRvZVwiXSIsICJiaXJ0aGRhdGUiOiAiW1wiblB1b1Fua1JGcTNCSWVBbTdBblhGQVwiLCBcIjE5NDAtMDEtMDFcIl0iLCAiYWRkcmVzcyI6IHsicmVnaW9uIjogIltcIkcwMk5TclFmakZYUTdJbzA5c3lhakFcIiwgXCJBbnlzdGF0ZVwiXSIsICJjb3VudHJ5IjogIltcImxrbHhGNWpNWWxHVFBVb3ZNTkl2Q0FcIiwgXCJVU1wiXSJ9fX0.KKjTUmWQGQl2WsdyFTacR063cvccnZ3IwO_3xOCbBT1-yD3EZvXBjOPi4-QAu1798dU99uLtEShI8A9wZdS-01-szsK8wrbKghNeJobkFeIYdo4eBGATFUOy9HG_m_fudGXVzrlEkYjWQAh0oA47tnDKBhlvb-Wgpylt3L5ABMTMyUABhdsJhTPIGoDUfk2VFvUixvH6NuppJTZazLCqR196tnI0LDL51W-e-RHVS_MAEIeex5TbLZxKFmdyyT49FnocvKM1lXGtBS6Yc73vNAiQ-GEmN0PUZaOzsnVlwJA6xVbwzjBlw4BDzvpJ3NEBik_iI4RAiwCOA-FnReokEw"

        val releaseClaims = SimpleCredential(givenName = "", familyName = "", address = Address(region = "", country = ""), birthdate = "")
        val presentationGen = createPresentation(credential, releaseClaims, verifier, nonce, holderKey)

        val (sdJwtGen, sdJwtRGen) = splitPresentation(presentationGen)
        val (sdJwt, sdJwtR) = splitPresentation(presentation)
        assertEquals(sdJwt, sdJwtGen)
        assertEquals(sdJwtR.jwtClaimsSet, sdJwtRGen.jwtClaimsSet)

        // Verify
        val verifiedSimpleCredential = verifyPresentation<SimpleCredential>(presentation, trustedIssuers, nonce, verifier)

        println("Verified credential: $verifiedSimpleCredential")

        val simpleCredential = SimpleCredential(
            givenName = "John",
            familyName = "Doe",
            birthdate = "1940-01-01",
            address = Address(region = "Anystate", country = "US")
        )
        assertEquals(simpleCredential, verifiedSimpleCredential)
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
        val nationality: Set<String>? = null,
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
        @SerialName("verified_claims") val verifiedClaims: VerifiedClaims? = null,
        @SerialName("birth_middle_name") val birthMiddleName: String? = null,
        val salutation: String? = null,
        val msisdn: String? = null
    )

    @Test
    internal fun complexTest() {
        println("==========================================")
        println("============== Complex Test ==============")
        println("==========================================")

        // Compare presentations
        val credential = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxNTgxMCwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InZlcmlmaWVkX2NsYWltcyI6IHsidmVyaWZpY2F0aW9uIjogeyJ0cnVzdF9mcmFtZXdvcmsiOiAidzFtUDRvUGNfSjl0aEJleDBUYVFpMXZneEZtcnVRSnhaWUxGbmtORk1hSSIsICJ0aW1lIjogIlB1M2kwQ1dyUFZMSlctTFQzMHlGMWJGQlBQMTVCNi11S2szUG5HRGZsdjgiLCAidmVyaWZpY2F0aW9uX3Byb2Nlc3MiOiAiOEhxSVhSbWN6c2RZT1p6R2NMcUk1LWw5eE41UWJLMlhEdFhtZGZIN3otNCIsICJldmlkZW5jZSI6IFt7InR5cGUiOiAiVG5MdXFHR1FtNmpmZU9vYTV1WDFkaUtBTlVQdWgtekhycEJGZFg5TVItZyIsICJtZXRob2QiOiAiU2FnbWFrb1N1LVgtWFVQSUMzRWdkckVFd0lXeFJXWFg0LWk2OFg5VHlFbyIsICJ0aW1lIjogImxkMmM1b1lEUnRRY2ZVNlB6b2dQa3hfOTVXWXFocUlKTlZSTW5mY3NpY1kiLCAiZG9jdW1lbnQiOiB7InR5cGUiOiAidWZXakRhQWE1NE1uSGVqaTJaVVVIRGRucFo5eng2Q1VHNnVSMjhWTXRzUSIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiYTRHTXVjVTdaYjA2MHIwU3ZkN2h1WTZRaG8xYklmM3YxVTVCdlBSOHE2WSIsICJjb3VudHJ5IjogIjEzNWs5TTBtMlNDbllSdU9mSHVZU2NZVlMycTNlZVk3SUl0Z3lSc2FCVDgifSwgIm51bWJlciI6ICJjVXZPeExVcDhSVjdUVFZsaUVpdS1UUUllbC1Mc0U4RS1YZlVnZnFrNWdrIiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiTklzOG9sSm5KT3Y0SjFxSUVCS3VUczJzRUZzNGZnR0poTnFNNnhkUXQ3RSIsICJkYXRlX29mX2V4cGlyeSI6ICJIVFIzN3ZMdEFOVDZNV2stOWRCcWVrRnBDdmFURzd6TmYxemU1NnJuVjY0In19XX0sICJjbGFpbXMiOiB7ImdpdmVuX25hbWUiOiAiTkI5WEhfeUpLcUtPaFhEbVhrWktwTUNrUmJPbU9UZDhicUpGWURKWVFuUSIsICJmYW1pbHlfbmFtZSI6ICJoQVViSjY2WllMOVZKTGJqc0RwbVNzMmU5RmZfT2hpbV9XUjRid1p5dm9RIiwgImJpcnRoZGF0ZSI6ICI2WE9SNGs1NkJnV2s1dG5OaXNtYm1FSHZvR1g3UlJmeTZaOEhFTmw5NmNVIiwgInBsYWNlX29mX2JpcnRoIjogeyJjb3VudHJ5IjogIkNMVGxodXkxM1dXYzNfSVNvbjFrRXlwRnd2Q21maExTcEdVTUN5QVVnNjgiLCAibG9jYWxpdHkiOiAiQVFvWDhpeEdwei1pcHdlRUdsQy0ydW1xd3lRZGhqSWVpVUJfVEtXY0UyRSJ9LCAibmF0aW9uYWxpdGllcyI6ICJuZm9jX19RS2xNVUhvZG14d2xZLUtwLTZld2dYM0NkSzdJYTBSSkhJWFZvIiwgImFkZHJlc3MiOiAibmduTzR1UWVPa3RNN1lkRkQ4eDgyZG9TN1dKbmxabnEtclFFX1JmdUJTSSJ9fSwgImJpcnRoX21pZGRsZV9uYW1lIjogIkZlRlN3ZDlkcnlwRVB0V1ZnSVo0Mk45al95b3N0dDFEczVQQnB4VDNSbmciLCAic2FsdXRhdGlvbiI6ICI1N0NNaHZBU1FNTnV6dVEwYV9CMV9WWDVYZEg3M1RjdVB4eVdHaW9yajVnIiwgIm1zaXNkbiI6ICJsZUtiQjBybzZxM2pyVnJhQ3F0NDQzdWFHWlZaaXNEM2lHckt1S0UybXFNIn19.3qCYGcV5PngUeKJkyQ_FSK44X6ziB4LASYz1G00NoYCSWsJ05Paqg7FGN_G1BdG-qSM1M39dtvjHEL5bgt02OzYpfpvY6ivWTXOWP9zBnitO00a3SqCh4-U06zGu4amx-Ma0s4Vj9tNItveiYHsDiwpwiL1DJCcIvG83i_dTMA2esHi256q9DiGuPLk9b4cPfkWMeOM_i7CakPi5s8F2mBUh0c0CZUkDDTctnN68OcWEcKvO7ReTNkGHZi7TpxqgmsHHgIGQwyDytFkkGTMgvlbpg4sIqwLUE3c910jpJ0JAiawUoKRF4H7NZ3PSg9rlj-QUHyGX5wIiJ3uy78Ng5A.eyJzZF9yZWxlYXNlIjogeyJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsidHJ1c3RfZnJhbWV3b3JrIjogIltcIjJHTEM0MnNLUXZlQ2ZHZnJ5TlJOOXdcIiwgXCJkZV9hbWxcIl0iLCAidGltZSI6ICJbXCJlbHVWNU9nM2dTTklJOEVZbnN4QV9BXCIsIFwiMjAxMi0wNC0yM1QxODoyNVpcIl0iLCAidmVyaWZpY2F0aW9uX3Byb2Nlc3MiOiAiW1wiNklqN3RNLWE1aVZQR2JvUzV0bXZWQVwiLCBcImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzdcIl0iLCAiZXZpZGVuY2UiOiBbeyJ0eXBlIjogIltcImVJOFpXbTlRbktQcE5QZU5lbkhkaFFcIiwgXCJkb2N1bWVudFwiXSIsICJtZXRob2QiOiAiW1wiUWdfTzY0enFBeGU0MTJhMTA4aXJvQVwiLCBcInBpcHBcIl0iLCAidGltZSI6ICJbXCJBSngtMDk1VlBycFR0TjRRTU9xUk9BXCIsIFwiMjAxMi0wNC0yMlQxMTozMFpcIl0iLCAiZG9jdW1lbnQiOiB7InR5cGUiOiAiW1wiUGMzM0pNMkxjaGNVX2xIZ2d2X3VmUVwiLCBcImlkY2FyZFwiXSIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiW1wiRzAyTlNyUWZqRlhRN0lvMDlzeWFqQVwiLCBcIlN0YWR0IEF1Z3NidXJnXCJdIiwgImNvdW50cnkiOiAiW1wibGtseEY1ak1ZbEdUUFVvdk1OSXZDQVwiLCBcIkRFXCJdIn0sICJudW1iZXIiOiAiW1wiblB1b1Fua1JGcTNCSWVBbTdBblhGQVwiLCBcIjUzNTU0NTU0XCJdIiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiW1wiNWJQczFJcXVaTmEwaGthRnp6elpOd1wiLCBcIjIwMTAtMDMtMjNcIl0iLCAiZGF0ZV9vZl9leHBpcnkiOiAiW1wiNWEyVzBfTnJsRVp6ZnFta183UHEtd1wiLCBcIjIwMjAtMDMtMjJcIl0ifX1dfSwgImNsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRXCIsIFwiTWF4XCJdIiwgImZhbWlseV9uYW1lIjogIltcIkhiUTRYOHNyVlczUUR4bklKZHF5T0FcIiwgXCJNZWllclwiXSIsICJiaXJ0aGRhdGUiOiAiW1wiQzlHU291anZpSnF1RWdZZm9qQ2IxQVwiLCBcIjE5NTYtMDEtMjhcIl0iLCAicGxhY2Vfb2ZfYmlydGgiOiB7ImNvdW50cnkiOiAiW1wia3g1a0YxN1YteDBKbXdVeDl2Z3Z0d1wiLCBcIkRFXCJdIiwgImxvY2FsaXR5IjogIltcIkgzbzF1c3dQNzYwRmkyeWVHZFZDRVFcIiwgXCJNdXN0ZXJzdGFkdFwiXSJ9LCAibmF0aW9uYWxpdGllcyI6ICJbXCJPQktsVFZsdkxnLUFkd3FZR2JQOFpBXCIsIFtcIkRFXCJdXSIsICJhZGRyZXNzIjogIltcIk0wSmI1N3Q0MXVicmtTdXlyRFQzeEFcIiwge1wibG9jYWxpdHlcIjogXCJNYXhzdGFkdFwiLCBcInBvc3RhbF9jb2RlXCI6IFwiMTIzNDRcIiwgXCJjb3VudHJ5XCI6IFwiREVcIiwgXCJzdHJlZXRfYWRkcmVzc1wiOiBcIkFuIGRlciBXZWlkZSAyMlwifV0ifX0sICJiaXJ0aF9taWRkbGVfbmFtZSI6ICJbXCJEc210S05ncFY0ZEFIcGpyY2Fvc0F3XCIsIFwiVGltb3RoZXVzXCJdIiwgInNhbHV0YXRpb24iOiAiW1wiZUs1bzVwSGZndXBQcGx0ajFxaEFKd1wiLCBcIkRyLlwiXSIsICJtc2lzZG4iOiAiW1wiajdBRGRiMFVWYjBMaTBjaVBjUDBld1wiLCBcIjQ5MTIzNDU2Nzg5XCJdIn19"
        val presentation = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiY25mIjogeyJrdHkiOiAiUlNBIiwgIm4iOiAicG00Yk9IQmctb1loQXlQV3pSNTZBV1gzclVJWHAxMV9JQ0RrR2dTNlczWldMdHMtaHp3STN4NjU2NTlrZzRoVm85ZGJHb0NKRTNaR0ZfZWFldEUzMFVoQlVFZ3BHd3JEclFpSjl6cXBybWNGZnIzcXZ2a0dqdHRoOFpnbDFlTTJiSmNPd0U3UENCSFdUS1dZczE1MlI3ZzZKZzJPVnBoLWE4cnEtcTc5TWhLRzVRb1dfbVR6MTBRVF82SDRjN1BqV0cxZmpoOGhwV05uYlBfcHY2ZDF6U3daZmM1Zmw2eVZSTDBEVjBWM2xHSEtlMldxZl9lTkdqQnJCTFZrbERUazgtc3RYX01XTGNSLUVHbVhBT3YwVUJXaXRTX2RYSktKdS12WEp5dzE0bkhTR3V4VElLMmh4MXB0dE1mdDlDc3ZxaW1YS2VEVFUxNHFRTDFlRTdpaGN3IiwgImUiOiAiQVFBQiJ9LCAiaWF0IjogMTY2MDUxNTgxMCwgImV4cCI6IDI1MjQ2MDgwMDAsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2IiwgInNkX2RpZ2VzdHMiOiB7InZlcmlmaWVkX2NsYWltcyI6IHsidmVyaWZpY2F0aW9uIjogeyJ0cnVzdF9mcmFtZXdvcmsiOiAidzFtUDRvUGNfSjl0aEJleDBUYVFpMXZneEZtcnVRSnhaWUxGbmtORk1hSSIsICJ0aW1lIjogIlB1M2kwQ1dyUFZMSlctTFQzMHlGMWJGQlBQMTVCNi11S2szUG5HRGZsdjgiLCAidmVyaWZpY2F0aW9uX3Byb2Nlc3MiOiAiOEhxSVhSbWN6c2RZT1p6R2NMcUk1LWw5eE41UWJLMlhEdFhtZGZIN3otNCIsICJldmlkZW5jZSI6IFt7InR5cGUiOiAiVG5MdXFHR1FtNmpmZU9vYTV1WDFkaUtBTlVQdWgtekhycEJGZFg5TVItZyIsICJtZXRob2QiOiAiU2FnbWFrb1N1LVgtWFVQSUMzRWdkckVFd0lXeFJXWFg0LWk2OFg5VHlFbyIsICJ0aW1lIjogImxkMmM1b1lEUnRRY2ZVNlB6b2dQa3hfOTVXWXFocUlKTlZSTW5mY3NpY1kiLCAiZG9jdW1lbnQiOiB7InR5cGUiOiAidWZXakRhQWE1NE1uSGVqaTJaVVVIRGRucFo5eng2Q1VHNnVSMjhWTXRzUSIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiYTRHTXVjVTdaYjA2MHIwU3ZkN2h1WTZRaG8xYklmM3YxVTVCdlBSOHE2WSIsICJjb3VudHJ5IjogIjEzNWs5TTBtMlNDbllSdU9mSHVZU2NZVlMycTNlZVk3SUl0Z3lSc2FCVDgifSwgIm51bWJlciI6ICJjVXZPeExVcDhSVjdUVFZsaUVpdS1UUUllbC1Mc0U4RS1YZlVnZnFrNWdrIiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiTklzOG9sSm5KT3Y0SjFxSUVCS3VUczJzRUZzNGZnR0poTnFNNnhkUXQ3RSIsICJkYXRlX29mX2V4cGlyeSI6ICJIVFIzN3ZMdEFOVDZNV2stOWRCcWVrRnBDdmFURzd6TmYxemU1NnJuVjY0In19XX0sICJjbGFpbXMiOiB7ImdpdmVuX25hbWUiOiAiTkI5WEhfeUpLcUtPaFhEbVhrWktwTUNrUmJPbU9UZDhicUpGWURKWVFuUSIsICJmYW1pbHlfbmFtZSI6ICJoQVViSjY2WllMOVZKTGJqc0RwbVNzMmU5RmZfT2hpbV9XUjRid1p5dm9RIiwgImJpcnRoZGF0ZSI6ICI2WE9SNGs1NkJnV2s1dG5OaXNtYm1FSHZvR1g3UlJmeTZaOEhFTmw5NmNVIiwgInBsYWNlX29mX2JpcnRoIjogeyJjb3VudHJ5IjogIkNMVGxodXkxM1dXYzNfSVNvbjFrRXlwRnd2Q21maExTcEdVTUN5QVVnNjgiLCAibG9jYWxpdHkiOiAiQVFvWDhpeEdwei1pcHdlRUdsQy0ydW1xd3lRZGhqSWVpVUJfVEtXY0UyRSJ9LCAibmF0aW9uYWxpdGllcyI6ICJuZm9jX19RS2xNVUhvZG14d2xZLUtwLTZld2dYM0NkSzdJYTBSSkhJWFZvIiwgImFkZHJlc3MiOiAibmduTzR1UWVPa3RNN1lkRkQ4eDgyZG9TN1dKbmxabnEtclFFX1JmdUJTSSJ9fSwgImJpcnRoX21pZGRsZV9uYW1lIjogIkZlRlN3ZDlkcnlwRVB0V1ZnSVo0Mk45al95b3N0dDFEczVQQnB4VDNSbmciLCAic2FsdXRhdGlvbiI6ICI1N0NNaHZBU1FNTnV6dVEwYV9CMV9WWDVYZEg3M1RjdVB4eVdHaW9yajVnIiwgIm1zaXNkbiI6ICJsZUtiQjBybzZxM2pyVnJhQ3F0NDQzdWFHWlZaaXNEM2lHckt1S0UybXFNIn19.3qCYGcV5PngUeKJkyQ_FSK44X6ziB4LASYz1G00NoYCSWsJ05Paqg7FGN_G1BdG-qSM1M39dtvjHEL5bgt02OzYpfpvY6ivWTXOWP9zBnitO00a3SqCh4-U06zGu4amx-Ma0s4Vj9tNItveiYHsDiwpwiL1DJCcIvG83i_dTMA2esHi256q9DiGuPLk9b4cPfkWMeOM_i7CakPi5s8F2mBUh0c0CZUkDDTctnN68OcWEcKvO7ReTNkGHZi7TpxqgmsHHgIGQwyDytFkkGTMgvlbpg4sIqwLUE3c910jpJ0JAiawUoKRF4H7NZ3PSg9rlj-QUHyGX5wIiJ3uy78Ng5A.eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZExZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJ5b3hDaURtNXNWUC1PVE5ZdGFfRERnIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVhc2UiOiB7InZlcmlmaWVkX2NsYWltcyI6IHsidmVyaWZpY2F0aW9uIjogeyJ0cnVzdF9mcmFtZXdvcmsiOiAiW1wiMkdMQzQyc0tRdmVDZkdmcnlOUk45d1wiLCBcImRlX2FtbFwiXSIsICJ0aW1lIjogIltcImVsdVY1T2czZ1NOSUk4RVluc3hBX0FcIiwgXCIyMDEyLTA0LTIzVDE4OjI1WlwiXSIsICJldmlkZW5jZSI6IFt7InR5cGUiOiAiW1wiZUk4WldtOVFuS1BwTlBlTmVuSGRoUVwiLCBcImRvY3VtZW50XCJdIn1dfSwgImNsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRXCIsIFwiTWF4XCJdIiwgImZhbWlseV9uYW1lIjogIltcIkhiUTRYOHNyVlczUUR4bklKZHF5T0FcIiwgXCJNZWllclwiXSIsICJiaXJ0aGRhdGUiOiAiW1wiQzlHU291anZpSnF1RWdZZm9qQ2IxQVwiLCBcIjE5NTYtMDEtMjhcIl0iLCAicGxhY2Vfb2ZfYmlydGgiOiB7ImNvdW50cnkiOiAiW1wia3g1a0YxN1YteDBKbXdVeDl2Z3Z0d1wiLCBcIkRFXCJdIn19fX19.ERvFEWtADBHfG_MLPDcp0Yam4O3F92lJp19fV-_D3tRmnfC2zpl6wiXLl3ZVf-m_mbIofxnpMuVvhUREifdyFfxFuoNPoVCQArsFxaY77VG_fn-AiY21KH73MY5aedx-twNYeIoPWqGs_5qofSBzJ-OVD-G-cMtD_o30EiEyJiEYinamLwS9v_WocQDtyV8W1O0P0uk6vhtG4AdefobvFqeosmLDsMX3uy0Hwe6cW2Nusoz3Z0NllvTPJtQr4aB39DCNXdEbmRP1MPuEgJz4j0Is8mIr2TfXFFdM6Mbh1emWbYObuqhnnK7YOdJBh01FB2bsY5cldAj58wjOmRbj0g"

        val releaseClaims = ComplexCredential(verifiedClaims = VerifiedClaims(
            verification = Verification(trustFramwork = "", time = "", evidence = setOf(Evidence(type = ""))),
            claims = Claims(givenName = "", familyName = "", birthdate = "", placeOfBirth = PlaceOfBirth(country = ""))
        ))
        val presentationGen = createPresentation(credential, releaseClaims, verifier, nonce, holderKey)

        val (sdJwtGen, sdJwtRGen) = splitPresentation(presentationGen)
        val (sdJwt, sdJwtR) = splitPresentation(presentation)
        assertEquals(sdJwt, sdJwtGen)
        assertEquals(sdJwtR.jwtClaimsSet, sdJwtRGen.jwtClaimsSet)

        // Verify
        val verifiedComplexCredential = verifyPresentation<ComplexCredential>(presentation, trustedIssuers, nonce, verifier)

        println("Verified credential: $verifiedComplexCredential")

        val complexCredential = ComplexCredential(
            VerifiedClaims(
                verification = Verification(
                    trustFramwork = "de_aml",
                    time = "2012-04-23T18:25Z",
                    evidence = setOf(Evidence(type = "document"))
                ),
                claims = Claims(givenName = "Max", familyName = "Meier", birthdate = "1956-01-28", placeOfBirth = PlaceOfBirth(country = "DE"))
            )
        )
        assertEquals(complexCredential, verifiedComplexCredential)
    }
}