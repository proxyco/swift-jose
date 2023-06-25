// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
@testable import JOSE
import secp256k1
import XCTest

final class JWETests: XCTestCase {
    // See https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
    func test_RFC7516_Appendix_A_1() throws {
        let plaintext = "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!

        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"RSA",
             "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
                  cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
                  psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
                  sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
                  tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
                  YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
             "e":"AQAB",
             "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N
                  WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9
                  3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk
                  qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl
                  t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd
                  VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
             "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-
                  SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf
                  fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
             "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm
                  UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX
                  IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
             "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL
                  hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827
                  rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
             "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj
                  ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB
                  UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
             "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7
                  AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3
                  eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .rsaOAEP,
                encryptionAlgorithm: .a256GCM
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: .init([
                177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
                212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
                234, 64, 252,
            ]),
            initializationVector: .init([
                227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219,
            ])
        )

        // Note: Due to 'RSA-OAEP' encryption's non-deterministic nature, serialization won't match the [test vector](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1.7)
        // However, successful decryption remains essential.

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)

        let receivedPlaintextTestVector = try JWE.decrypt(
            serialization: """
            eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
            OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
            ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
            Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
            mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
            1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
            6UklfCpIMfIjf7iGdXKHzg.
            48V1_ALb6US04U3b.
            5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
            SdiwkIr3ajwQzaBtQD_A.
            XFBoMYUZodetZdvTiFvSkQ
            """.replacingWhiteSpacesAndNewLines(),
            using: recipientJWK
        )

        XCTAssertEqual(plaintext, receivedPlaintextTestVector)
    }

    // Note: Omitting example from A.2., as it will be tested in A.4.

    // See https://www.rfc-editor.org/rfc/rfc7516#appendix-A.3
    func test_RFC7516_Appendix_A_3() throws {
        let plaintext = "Live long and prosper.".data(using: .utf8)!

        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"oct",
             "k":"GawgguFyGrWKav7AX4VKUg"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .a128KW,
                encryptionAlgorithm: .a128CBCHS256
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: .init([
                4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                44, 207,
            ]),
            initializationVector: .init([
                3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
                101,
            ])
        )

        XCTAssertEqual(
            serialization,
            """
            eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
            6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.
            AxY8DCtDaGlsbGljb3RoZQ.
            KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.
            U0m_YmjN04DJvceFICbCVQ
            """.replacingWhiteSpacesAndNewLines()
        )

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7516#appendix-A.4
    func test_RFC7516_Appendix_A_4() throws {
        let plaintext = "Live long and prosper.".data(using: .utf8)!

        var recipient1JWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"RSA",
             "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl
                  UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre
                  cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_
                  7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI
                  Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU
                  7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
             "e":"AQAB",
             "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq
                  1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry
                  nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_
                  0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj
                  -VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj
                  T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
             "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68
                  ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP
                  krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
             "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y
                  BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN
                  -3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
             "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv
                  ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra
                  Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
             "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff
                  7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_
                  odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
             "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC
                  tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ
                  B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        recipient1JWK.keyID = "2011-04-29"

        var recipient2JWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"oct",
             "k":"GawgguFyGrWKav7AX4VKUg"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        recipient2JWK.keyID = "7"

        let recipients: [JWE.Recipient] = [
            try .init(
                header: JSONDecoder().decode(
                    JOSEHeader.self,
                    from: """
                    {"alg":"RSA1_5","kid":"2011-04-29"}
                    """.data(using: .utf8)!
                ),
                jwk: recipient1JWK
            ),
            try .init(
                header: JSONDecoder().decode(
                    JOSEHeader.self,
                    from: """
                    {"alg":"A128KW","kid":"7"}
                    """.data(using: .utf8)!
                ),
                jwk: recipient2JWK
            ),
        ]

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipients,
            protectedHeader: .init(encryptionAlgorithm: .a128CBCHS256),
            sharedUnprotectedHeader: .init(jwkSetURL: "https://server.example.com/keys.jwks"),
            contentEncryptionKey: .init([
                4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                44, 207,
            ]),
            initializationVector: Base64URL.decode("AxY8DCtDaGlsbGljb3RoZQ"),
            jsonEncoder: JSONEncoder()
        )

        // Note: Due to 'RSA1_5' encryption's non-deterministic nature, serialization won't match the [test vector](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.4.7)
        // However, successful decryption remains essential.

        let receivedPlaintext = try JWE.decrypt(
            serialization: serialization,
            using: [
                recipient1JWK,
                recipient2JWK,
            ]
        )

        XCTAssertEqual(plaintext, receivedPlaintext)

        let receivedPlaintextTestVector = try JWE.decrypt(
            serialization: """
            {
             "protected":
              "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
             "unprotected":
              {"jku":"https://server.example.com/keys.jwks"},
             "recipients":[
              {"header":
                {"alg":"RSA1_5","kid":"2011-04-29"},
               "encrypted_key":
                "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
                 kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
                 GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
                 YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
                 cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
                 wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
              {"header":
                {"alg":"A128KW","kid":"7"},
               "encrypted_key":
                "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
             "iv":
              "AxY8DCtDaGlsbGljb3RoZQ",
             "ciphertext":
              "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
             "tag":
              "Mz-VPPyU4RlcuYv1IwIvzw"
            }
            """.replacingWhiteSpacesAndNewLines(),
            using: [
                recipient1JWK,
                recipient2JWK,
            ]
        )

        XCTAssertEqual(plaintext, receivedPlaintextTestVector)
    }

    // See https://www.rfc-editor.org/rfc/rfc7518#appendix-C
    func test_RFC7518_Appendix_C() throws {
        let bobJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"EC",
             "crv":"P-256",
             "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
             "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
             "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        var protectedHeader: JOSEHeader? = try JSONDecoder().decode(
            JOSEHeader.self,
            from: """
            {"alg":"ECDH-ES",
             "enc":"A128GCM",
             "apu":"QWxpY2U",
             "apv":"Qm9i",
             "epk":
              {"kty":"EC",
               "crv":"P-256",
               "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
               "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
               "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
              }
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let agreedUponKey = try JWE.senderComputeAgreedUponKey(
            to: bobJWK,
            protectedHeader: &protectedHeader,
            joseHeader: protectedHeader!
        )

        XCTAssertEqual(Base64URL.encode(agreedUponKey), "VqqN6vgjbSBcIijNcacQGg")
    }

    let rfc7520_figure_72 = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!

    let rfc7520_figure_73 = """
    {
      "kty": "RSA",
      "kid": "frodo.baggins@hobbiton.example",
      "use": "enc",
      "n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
          HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
          6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
          NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
          R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
          pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
          VotGlvMQ",
      "e": "AQAB",
      "d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
          bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
          5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
          Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
          1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
          miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
          pzj85bQQ",
      "p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
          oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
          7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
          2VFmU",
      "q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
          F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
          9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
          d6Et0",
      "dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
          QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
          RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
          lo0rYU",
      "dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
          pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
          CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
          TkXlHE",
      "qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
          lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
          Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
          2bQ_mM"
    }
    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.1
    func test_RFC7520_Section_5_1() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_73)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .rsa1_5,
                encryptionAlgorithm: .a128CBCHS256,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
            V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo"),
            initializationVector: Base64URL.decode("bbd5sTkYwhAIqfHsx8DayA")
        )

        // Note: Due to 'RSA1_5' encryption's non-deterministic nature, serialization won't match the [output results](https://www.rfc-editor.org/rfc/rfc7520#section-5.1.5)
        // However, successful decryption remains essential.

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)

        let receivedPlaintextTestVector = try JWE.decrypt(
            serialization: """
            eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
            V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
            .
            laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF
            vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G
            Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG
            TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl
            zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh
            MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw
            .
            bbd5sTkYwhAIqfHsx8DayA
            .
            0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r
            aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O
            WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV
            yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0
            zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2
            O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW
            i7lzA6BP430m
            .
            kvKuFBXHe5mQr4lqgobAUg
            """.replacingWhiteSpacesAndNewLines(),
            using: recipientJWK
        )

        XCTAssertEqual(plaintext, receivedPlaintextTestVector)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.2
    func test_RFC7520_Section_5_2() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "RSA",
              "kid": "samwise.gamgee@hobbiton.example",
              "use": "enc",
              "n": "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRr
                  I4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-Fy
                  XJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnk
                  Nrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeSt
                  sqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M
                  5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIU
                  e7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBOD
                  FskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb
                  86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqB
                  SAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhO
                  OnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDa
                  iCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnT
                  yC0xhWBlsolZE",
              "e": "AQAB",
              "alg": "RSA-OAEP",
              "d": "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bx
                  cc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq
                  -B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT
                  2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9E
                  A-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876
                  DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIj
                  h1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r
                  -MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yD
                  F-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1L
                  oomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W
                  _IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28
                  S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c
                  9WsWgRzI-K8gE",
              "p": "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKgh
                  vM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsY
                  a_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3m
                  Y46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-
                  RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9s
                  fbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgP
                  gWCv5HoQ",
              "q": "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6Zy
                  KQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDc
                  qssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYG
                  RuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJ
                  aPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EX
                  e2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJ
                  JlXXnH8Q",
              "dp": "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xn
                  x5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQ
                  J_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72F
                  ZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3i
                  XjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGm
                  pKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9Lc
                  nwwT0jvoQ",
              "dq": "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1
                  VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM
                  1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fg
                  dyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrI
                  ChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2
                  AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iz
                  nBNCeOUIQ",
              "qi": "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCc
                  iRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80
                  oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMw
                  QqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl
                  27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4
                  UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq
                  8EzqZEKIA"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .rsaOAEP,
                encryptionAlgorithm: .a256GCM,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
            9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("mYMfsggkTAm0TbvtlFh2hyoXnbEzJQjMxmgLN3d8xXA"),
            initializationVector: Base64URL.decode("-nBoKLH0YkLZPSI9")
        )

        // Note: Due to 'RSA-OAEP' encryption's non-deterministic nature, serialization won't match the [output results](https://www.rfc-editor.org/rfc/rfc7520#section-5.2.5)
        // However, successful decryption remains essential.

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)

        let receivedPlaintextTestVector = try JWE.decrypt(
            serialization: """
            eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
            9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
            .
            rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi
            beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu
            cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58
            -Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx
            KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK
            IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7
            pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ
            fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3
            8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU
            06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5
            Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR
            s
            .
            -nBoKLH0YkLZPSI9
            .
            o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR
            L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw
            P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8
            iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML
            7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV
            maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw
            .
            UCGiqJxhBI3IFVdPalHHvA
            """.replacingWhiteSpacesAndNewLines(),
            using: recipientJWK
        )

        XCTAssertEqual(plaintext, receivedPlaintextTestVector)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.3
    func test_RFC7520_Section_5_3() throws {
        let plaintext = """
        {
          "keys": [
            {
              "kty": "oct",
              "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
              "use": "enc",
              "alg": "A128GCM",
              "k": "XctOhJAkA-pD9Lh7ZgW_2A"
            },
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            },
            {
              "kty": "oct",
              "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
              "use": "enc",
              "alg": "A256GCMKW",
              "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"
            }
          ]
        }
        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!

        let password = "entrap_o–peter_long–credit_tun".data(using: .utf8)!

        let recipientJWK = JWK(keyType: .octetSequence, key: password)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            encodedProtectedHeader: """
            eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3
            hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl
            bmMiOiJBMTI4Q0JDLUhTMjU2In0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("uwsjJXaBK407Qaf0_zpcpmr1Cs0CC50hIUEyGNEt3m0"),
            initializationVector: Base64URL.decode("VBiCzVHNoLiR3F4V82uoTQ")
        )

        let expectedSerialization = """
        eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3
        hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl
        bmMiOiJBMTI4Q0JDLUhTMjU2In0
        .
        d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g
        .
        VBiCzVHNoLiR3F4V82uoTQ
        .
        23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR
        sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l
        TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb
        6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL
        _SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd
        PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok
        AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-
        zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V
        3kobXZ77ulMwDs4p
        .
        0HlwodAhOCILG5SQ2LQ9dg
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7517.html#appendix-C
    func test_RFC7517_Appendix_C() throws {
        let plaintext = Data(Array(
            [123, 34, 107, 116, 121, 34, 58, 34, 82, 83, 65, 34, 44, 34, 107,
             105, 100, 34, 58, 34, 106, 117, 108, 105, 101, 116, 64, 99, 97, 112,
             117, 108, 101, 116, 46, 108, 105, 116, 34, 44, 34, 117, 115, 101, 34,
             58, 34, 101, 110, 99, 34, 44, 34, 110, 34, 58, 34, 116, 54, 81, 56,
             80, 87, 83, 105, 49, 100, 107, 74, 106, 57, 104, 84, 80, 56, 104, 78,
             89, 70, 108, 118, 97, 100, 77, 55, 68, 102, 108, 87, 57, 109, 87,
             101, 112, 79, 74, 104, 74, 54, 54, 119, 55, 110, 121, 111, 75, 49,
             103, 80, 78, 113, 70, 77, 83, 81, 82, 121, 79, 49, 50, 53, 71, 112,
             45, 84, 69, 107, 111, 100, 104, 87, 114, 48, 105, 117, 106, 106, 72,
             86, 120, 55, 66, 99, 86, 48, 108, 108, 83, 52, 119, 53, 65, 67, 71,
             103, 80, 114, 99, 65, 100, 54, 90, 99, 83, 82, 48, 45, 73, 113, 111,
             109, 45, 81, 70, 99, 78, 80, 56, 83, 106, 103, 48, 56, 54, 77, 119,
             111, 113, 81, 85, 95, 76, 89, 121, 119, 108, 65, 71, 90, 50, 49, 87,
             83, 100, 83, 95, 80, 69, 82, 121, 71, 70, 105, 78, 110, 106, 51, 81,
             81, 108, 79, 56, 89, 110, 115, 53, 106, 67, 116, 76, 67, 82, 119, 76,
             72, 76, 48, 80, 98, 49, 102, 69, 118, 52, 53, 65, 117, 82, 73, 117,
             85, 102, 86, 99, 80, 121, 83, 66, 87, 89, 110, 68, 121, 71, 120, 118,
             106, 89, 71, 68, 83, 77, 45, 65, 113, 87, 83, 57, 122, 73, 81, 50,
             90, 105, 108, 103, 84, 45, 71, 113, 85, 109, 105, 112, 103, 48, 88,
             79, 67, 48, 67, 99, 50, 48, 114, 103, 76, 101, 50, 121, 109, 76, 72,
             106, 112, 72, 99, 105, 67, 75, 86, 65, 98, 89, 53, 45, 76, 51, 50,
             45, 108, 83, 101, 90, 79, 45, 79, 115, 54, 85, 49, 53, 95, 97, 88,
             114, 107, 57, 71, 119, 56, 99, 80, 85, 97, 88, 49, 95, 73, 56, 115,
             76, 71, 117, 83, 105, 86, 100, 116, 51, 67, 95, 70, 110, 50, 80, 90,
             51, 90, 56, 105, 55, 52, 52, 70, 80, 70, 71, 71, 99, 71, 49, 113,
             115, 50, 87, 122, 45, 81, 34, 44, 34, 101, 34, 58, 34, 65, 81, 65,
             66, 34, 44, 34, 100, 34, 58, 34, 71, 82, 116, 98, 73, 81, 109, 104,
             79, 90, 116, 121, 115, 122, 102, 103, 75, 100, 103, 52, 117, 95, 78,
             45, 82, 95, 109, 90, 71, 85, 95, 57, 107, 55, 74, 81, 95, 106, 110,
             49, 68, 110, 102, 84, 117, 77, 100, 83, 78, 112, 114, 84, 101, 97,
             83, 84, 121, 87, 102, 83, 78, 107, 117, 97, 65, 119, 110, 79, 69, 98,
             73, 81, 86, 121, 49, 73, 81, 98, 87, 86, 86, 50, 53, 78, 89, 51, 121,
             98, 99, 95, 73, 104, 85, 74, 116, 102, 114, 105, 55, 98, 65, 88, 89,
             69, 82, 101, 87, 97, 67, 108, 51, 104, 100, 108, 80, 75, 88, 121, 57,
             85, 118, 113, 80, 89, 71, 82, 48, 107, 73, 88, 84, 81, 82, 113, 110,
             115, 45, 100, 86, 74, 55, 106, 97, 104, 108, 73, 55, 76, 121, 99,
             107, 114, 112, 84, 109, 114, 77, 56, 100, 87, 66, 111, 52, 95, 80,
             77, 97, 101, 110, 78, 110, 80, 105, 81, 103, 79, 48, 120, 110, 117,
             84, 111, 120, 117, 116, 82, 90, 74, 102, 74, 118, 71, 52, 79, 120,
             52, 107, 97, 51, 71, 79, 82, 81, 100, 57, 67, 115, 67, 90, 50, 118,
             115, 85, 68, 109, 115, 88, 79, 102, 85, 69, 78, 79, 121, 77, 113, 65,
             68, 67, 54, 112, 49, 77, 51, 104, 51, 51, 116, 115, 117, 114, 89, 49,
             53, 107, 57, 113, 77, 83, 112, 71, 57, 79, 88, 95, 73, 74, 65, 88,
             109, 120, 122, 65, 104, 95, 116, 87, 105, 90, 79, 119, 107, 50, 75,
             52, 121, 120, 72, 57, 116, 83, 51, 76, 113, 49, 121, 88, 56, 67, 49,
             69, 87, 109, 101, 82, 68, 107, 75, 50, 97, 104, 101, 99, 71, 56, 53,
             45, 111, 76, 75, 81, 116, 53, 86, 69, 112, 87, 72, 75, 109, 106, 79,
             105, 95, 103, 74, 83, 100, 83, 103, 113, 99, 78, 57, 54, 88, 53, 50,
             101, 115, 65, 81, 34, 44, 34, 112, 34, 58, 34, 50, 114, 110, 83, 79,
             86, 52, 104, 75, 83, 78, 56, 115, 83, 52, 67, 103, 99, 81, 72, 70,
             98, 115, 48, 56, 88, 98, 111, 70, 68, 113, 75, 117, 109, 51, 115, 99,
             52, 104, 51, 71, 82, 120, 114, 84, 109, 81, 100, 108, 49, 90, 75, 57,
             117, 119, 45, 80, 73, 72, 102, 81, 80, 48, 70, 107, 120, 88, 86, 114,
             120, 45, 87, 69, 45, 90, 69, 98, 114, 113, 105, 118, 72, 95, 50, 105,
             67, 76, 85, 83, 55, 119, 65, 108, 54, 88, 118, 65, 82, 116, 49, 75,
             107, 73, 97, 85, 120, 80, 80, 83, 89, 66, 57, 121, 107, 51, 49, 115,
             48, 81, 56, 85, 75, 57, 54, 69, 51, 95, 79, 114, 65, 68, 65, 89, 116,
             65, 74, 115, 45, 77, 51, 74, 120, 67, 76, 102, 78, 103, 113, 104, 53,
             54, 72, 68, 110, 69, 84, 84, 81, 104, 72, 51, 114, 67, 84, 53, 84,
             51, 121, 74, 119, 115, 34, 44, 34, 113, 34, 58, 34, 49, 117, 95, 82,
             105, 70, 68, 80, 55, 76, 66, 89, 104, 51, 78, 52, 71, 88, 76, 84, 57,
             79, 112, 83, 75, 89, 80, 48, 117, 81, 90, 121, 105, 97, 90, 119, 66,
             116, 79, 67, 66, 78, 74, 103, 81, 120, 97, 106, 49, 48, 82, 87, 106,
             115, 90, 117, 48, 99, 54, 73, 101, 100, 105, 115, 52, 83, 55, 66, 95,
             99, 111, 83, 75, 66, 48, 75, 106, 57, 80, 97, 80, 97, 66, 122, 103,
             45, 73, 121, 83, 82, 118, 118, 99, 81, 117, 80, 97, 109, 81, 117, 54,
             54, 114, 105, 77, 104, 106, 86, 116, 71, 54, 84, 108, 86, 56, 67, 76,
             67, 89, 75, 114, 89, 108, 53, 50, 122, 105, 113, 75, 48, 69, 95, 121,
             109, 50, 81, 110, 107, 119, 115, 85, 88, 55, 101, 89, 84, 66, 55, 76,
             98, 65, 72, 82, 75, 57, 71, 113, 111, 99, 68, 69, 53, 66, 48, 102,
             56, 48, 56, 73, 52, 115, 34, 44, 34, 100, 112, 34, 58, 34, 75, 107,
             77, 84, 87, 113, 66, 85, 101, 102, 86, 119, 90, 50, 95, 68, 98, 106,
             49, 112, 80, 81, 113, 121, 72, 83, 72, 106, 106, 57, 48, 76, 53, 120,
             95, 77, 79, 122, 113, 89, 65, 74, 77, 99, 76, 77, 90, 116, 98, 85,
             116, 119, 75, 113, 118, 86, 68, 113, 51, 116, 98, 69, 111, 51, 90,
             73, 99, 111, 104, 98, 68, 116, 116, 54, 83, 98, 102, 109, 87, 122,
             103, 103, 97, 98, 112, 81, 120, 78, 120, 117, 66, 112, 111, 79, 79,
             102, 95, 97, 95, 72, 103, 77, 88, 75, 95, 108, 104, 113, 105, 103,
             73, 52, 121, 95, 107, 113, 83, 49, 119, 89, 53, 50, 73, 119, 106, 85,
             110, 53, 114, 103, 82, 114, 74, 45, 121, 89, 111, 49, 104, 52, 49,
             75, 82, 45, 118, 122, 50, 112, 89, 104, 69, 65, 101, 89, 114, 104,
             116, 116, 87, 116, 120, 86, 113, 76, 67, 82, 86, 105, 68, 54, 99, 34,
             44, 34, 100, 113, 34, 58, 34, 65, 118, 102, 83, 48, 45, 103, 82, 120,
             118, 110, 48, 98, 119, 74, 111, 77, 83, 110, 70, 120, 89, 99, 75, 49,
             87, 110, 117, 69, 106, 81, 70, 108, 117, 77, 71, 102, 119, 71, 105,
             116, 81, 66, 87, 116, 102, 90, 49, 69, 114, 55, 116, 49, 120, 68,
             107, 98, 78, 57, 71, 81, 84, 66, 57, 121, 113, 112, 68, 111, 89, 97,
             78, 48, 54, 72, 55, 67, 70, 116, 114, 107, 120, 104, 74, 73, 66, 81,
             97, 106, 54, 110, 107, 70, 53, 75, 75, 83, 51, 84, 81, 116, 81, 53,
             113, 67, 122, 107, 79, 107, 109, 120, 73, 101, 51, 75, 82, 98, 66,
             121, 109, 88, 120, 107, 98, 53, 113, 119, 85, 112, 88, 53, 69, 76,
             68, 53, 120, 70, 99, 54, 70, 101, 105, 97, 102, 87, 89, 89, 54, 51,
             84, 109, 109, 69, 65, 117, 95, 108, 82, 70, 67, 79, 74, 51, 120, 68,
             101, 97, 45, 111, 116, 115, 34, 44, 34, 113, 105, 34, 58, 34, 108,
             83, 81, 105, 45, 119, 57, 67, 112, 121, 85, 82, 101, 77, 69, 114, 80,
             49, 82, 115, 66, 76, 107, 55, 119, 78, 116, 79, 118, 115, 53, 69, 81,
             112, 80, 113, 109, 117, 77, 118, 113, 87, 53, 55, 78, 66, 85, 99,
             122, 83, 99, 69, 111, 80, 119, 109, 85, 113, 113, 97, 98, 117, 57,
             86, 48, 45, 80, 121, 52, 100, 81, 53, 55, 95, 98, 97, 112, 111, 75,
             82, 117, 49, 82, 57, 48, 98, 118, 117, 70, 110, 85, 54, 51, 83, 72,
             87, 69, 70, 103, 108, 90, 81, 118, 74, 68, 77, 101, 65, 118, 109,
             106, 52, 115, 109, 45, 70, 112, 48, 111, 89, 117, 95, 110, 101, 111,
             116, 103, 81, 48, 104, 122, 98, 73, 53, 103, 114, 121, 55, 97, 106,
             100, 89, 121, 57, 45, 50, 108, 78, 120, 95, 55, 54, 97, 66, 90, 111,
             79, 85, 117, 57, 72, 67, 74, 45, 85, 115, 102, 83, 79, 73, 56, 34,
             125]
        ))

        let password = Data(Array(
            [84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108,
             105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32,
             109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103,
             101, 100, 46]
        ))

        let recipientJWK = JWK(keyType: .octetSequence, key: password)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            encodedProtectedHeader: """
            eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSn
            VKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5Ijoi
            andrK2pzb24ifQ
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Data(Array(
                [111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112,
                 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48,
                 253, 182]
            )),
            initializationVector: Data(Array(
                [97, 239, 99, 214, 171, 54, 216, 57, 145, 72, 7, 93, 34, 31, 149,
                 156]
            ))
        )

        let expectedSerialization = """
        eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSn
        VKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5Ijoi
        andrK2pzb24ifQ.
        TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA.
        Ye9j1qs22DmRSAddIh-VnA.
        AwhB8lxrlKjFn02LGWEqg27H4Tg9fyZAbFv3p5ZicHpj64QyHC44qqlZ3JEmnZTgQo
        wIqZJ13jbyHB8LgePiqUJ1hf6M2HPLgzw8L-mEeQ0jvDUTrE07NtOerBk8bwBQyZ6g
        0kQ3DEOIglfYxV8-FJvNBYwbqN1Bck6d_i7OtjSHV-8DIrp-3JcRIe05YKy3Oi34Z_
        GOiAc1EK21B11c_AE11PII_wvvtRiUiG8YofQXakWd1_O98Kap-UgmyWPfreUJ3lJP
        nbD4Ve95owEfMGLOPflo2MnjaTDCwQokoJ_xplQ2vNPz8iguLcHBoKllyQFJL2mOWB
        wqhBo9Oj-O800as5mmLsvQMTflIrIEbbTMzHMBZ8EFW9fWwwFu0DWQJGkMNhmBZQ-3
        lvqTc-M6-gWA6D8PDhONfP2Oib2HGizwG1iEaX8GRyUpfLuljCLIe1DkGOewhKuKkZ
        h04DKNM5Nbugf2atmU9OP0Ldx5peCUtRG1gMVl7Qup5ZXHTjgPDr5b2N731UooCGAU
        qHdgGhg0JVJ_ObCTdjsH4CF1SJsdUhrXvYx3HJh2Xd7CwJRzU_3Y1GxYU6-s3GFPbi
        rfqqEipJDBTHpcoCmyrwYjYHFgnlqBZRotRrS95g8F95bRXqsaDY7UgQGwBQBwy665
        d0zpvTasvfXf_c0MWAl-neFaKOW_Px6g4EUDjG1GWSXV9cLStLw_0ovdApDIFLHYHe
        PyagyHjouQUuGiq7BsYwYrwaF06tgB8hV8omLNfMEmDPJaZUzMuHw6tBDwGkzD-tS_
        ub9hxrpJ4UsOWnt5rGUyoN2N_c1-TQlXxm5oto14MxnoAyBQBpwIEgSH3Y4ZhwKBhH
        PjSo0cdwuNdYbGPpb-YUvF-2NZzODiQ1OvWQBRHSbPWYz_xbGkgD504LRtqRwCO7CC
        _CyyURi1sEssPVsMJRX_U4LFEOc82TiDdqjKOjRUfKK5rqLi8nBE9soQ0DSaOoFQZi
        GrBrqxDsNYiAYAmxxkos-i3nX4qtByVx85sCE5U_0MqG7COxZWMOPEFrDaepUV-cOy
        rvoUIng8i8ljKBKxETY2BgPegKBYCxsAUcAkKamSCC9AiBxA0UOHyhTqtlvMksO7AE
        hNC2-YzPyx1FkhMoS4LLe6E_pFsMlmjA6P1NSge9C5G5tETYXGAn6b1xZbHtmwrPSc
        ro9LWhVmAaA7_bxYObnFUxgWtK4vzzQBjZJ36UTk4OTB-JvKWgfVWCFsaw5WCHj6Oo
        4jpO7d2yN7WMfAj2hTEabz9wumQ0TMhBduZ-QON3pYObSy7TSC1vVme0NJrwF_cJRe
        hKTFmdlXGVldPxZCplr7ZQqRQhF8JP-l4mEQVnCaWGn9ONHlemczGOS-A-wwtnmwjI
        B1V_vgJRf4FdpV-4hUk4-QLpu3-1lWFxrtZKcggq3tWTduRo5_QebQbUUT_VSCgsFc
        OmyWKoj56lbxthN19hq1XGWbLGfrrR6MWh23vk01zn8FVwi7uFwEnRYSafsnWLa1Z5
        TpBj9GvAdl2H9NHwzpB5NqHpZNkQ3NMDj13Fn8fzO0JB83Etbm_tnFQfcb13X3bJ15
        Cz-Ww1MGhvIpGGnMBT_ADp9xSIyAM9dQ1yeVXk-AIgWBUlN5uyWSGyCxp0cJwx7HxM
        38z0UIeBu-MytL-eqndM7LxytsVzCbjOTSVRmhYEMIzUAnS1gs7uMQAGRdgRIElTJE
        SGMjb_4bZq9s6Ve1LKkSi0_QDsrABaLe55UY0zF4ZSfOV5PMyPtocwV_dcNPlxLgNA
        D1BFX_Z9kAdMZQW6fAmsfFle0zAoMe4l9pMESH0JB4sJGdCKtQXj1cXNydDYozF7l8
        H00BV_Er7zd6VtIw0MxwkFCTatsv_R-GsBCH218RgVPsfYhwVuT8R4HarpzsDBufC4
        r8_c8fc9Z278sQ081jFjOja6L2x0N_ImzFNXU6xwO-Ska-QeuvYZ3X_L31ZOX4Llp-
        7QSfgDoHnOxFv1Xws-D5mDHD3zxOup2b2TppdKTZb9eW2vxUVviM8OI9atBfPKMGAO
        v9omA-6vv5IxUH0-lWMiHLQ_g8vnswp-Jav0c4t6URVUzujNOoNd_CBGGVnHiJTCHl
        88LQxsqLHHIu4Fz-U2SGnlxGTj0-ihit2ELGRv4vO8E1BosTmf0cx3qgG0Pq0eOLBD
        IHsrdZ_CCAiTc0HVkMbyq1M6qEhM-q5P6y1QCIrwg.
        0HFmhOzsQ98nNWJjIHkR7A
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.4
    func test_RFC7520_Section_5_4() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_108)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .ecdhESA128KW,
                encryptionAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID,
                ephemeralPublicKey: JSONDecoder().decode(
                    JWK.self,
                    from: """
                    {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuE
                          DsQ6wNdNg3",
                      "y": "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-
                          JdaY8tb7E0",
                      "d": "D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8W
                          fwhinUfWJg"
                    }
                    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                )
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH
            Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt
            Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH
            hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy
            ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT
            h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("Nou2ueKlP70ZXDbq9UrRwg"),
            initializationVector: Base64URL.decode("mH-G2zVqgztUtnW_")
        )

        let expectedSerialization = """
        eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH
        Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt
        Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH
        hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy
        ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT
        h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
        .
        0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2
        .
        mH-G2zVqgztUtnW_
        .
        tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP
        WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0
        IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc
        Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0
        3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu
        07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ
        .
        WuGzxmcreYjpHGJoa17EBg
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.5
    func test_RFC7520_Section_5_5() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "EC",
              "kid": "meriadoc.brandybuck@buckland.example",
              "use": "enc",
              "crv": "P-256",
              "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
              "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
              "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .ecdhES,
                encryptionAlgorithm: .a128CBCHS256,
                keyID: recipientJWK.keyID,
                ephemeralPublicKey: JSONDecoder().decode(
                    JWK.self,
                    from: """
                    {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
                      "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
                      "d": "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM"
                    }
                    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                )
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW
            NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi
            LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF
            lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0
            RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ
            """.replacingWhiteSpacesAndNewLines(),
            initializationVector: Base64URL.decode("yc9N8v5sYyv3iGQT926IUg")
        )

        let expectedSerialization = """
        eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW
        NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi
        LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF
        lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0
        RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ
        .
        .
        yc9N8v5sYyv3iGQT926IUg
        .
        BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9
        IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e
        vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-
        IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI
        -sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7
        MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61
        95_JGG2m9Csg
        .
        WCCkNa-x4BeB9hIDIfFuhg
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.6
    func test_RFC7520_Section_5_6() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
              "use": "enc",
              "alg": "A128GCM",
              "k": "XctOhJAkA-pD9Lh7ZgW_2A"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )

        let sharedSymmetricKey: Data = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
              "use": "enc",
              "alg": "A128GCM",
              "k": "XctOhJAkA-pD9Lh7ZgW_2A"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        ).key!

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .direct,
                encryptionAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT
            diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: sharedSymmetricKey,
            initializationVector: Base64URL.decode("refa467QzzKx6QAB")
        )

        let expectedSerialization = """
        eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT
        diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
        .
        .
        refa467QzzKx6QAB
        .
        JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y
        hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM
        DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_
        BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5
        g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn
        ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp
        .
        vbb32Xvllea2OtmHAdccRQ
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(
            serialization: serialization,
            using: recipientJWK,
            sharedSymmetricKey: sharedSymmetricKey
        )

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.7
    func test_RFC7520_Section_5_7() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_138)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .a256GCMKW,
                encryptionAlgorithm: .a128CBCHS256,
                keyID: "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                initializationVector: Base64URL.decode("KkYT0GX_2jHlfqN_"),
                authenticationTag: Base64URL.decode("kfPduVQ3T3H6vnewt--ksw")
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj
            IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3
            IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni
            J9
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("UWxARpat23nL9ReIj4WG3D1ee9I4r-Mv5QLuFXdy_rE"),
            initializationVector: Base64URL.decode("gz6NjyEFNm_vm8Gj6FwoFQ")
        )

        let expectedSerialization = """
        eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj
        IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3
        IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni
        J9
        .
        lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok
        .
        gz6NjyEFNm_vm8Gj6FwoFQ
        .
        Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaE
        eVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCz
        LjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFq
        hpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hde
        b6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0Jtj
        xAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR
        1B-gxpNk3xWU
        .
        DKW7jrb4WaRSNfbXVPlT5g
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    let rfc7520_figure_108 = """
    {
      "kty": "EC",
      "kid": "peregrin.took@tuckborough.example",
      "use": "enc",
      "crv": "P-384",
      "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQL
          pe2FpxBmu2",
      "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-
          SkgaFL1ETP",
      "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0Idn
          YK2xDlZh-j"
    }
    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!

    let rfc7520_figure_138 = """
    {
      "kty": "oct",
      "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
      "use": "enc",
      "alg": "A256GCMKW",
      "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"
    }
    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!

    let rfc7520_figure_151 = """
    {
      "kty": "oct",
      "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
      "use": "enc",
      "alg": "A128KW",
      "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
    }
    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.8
    func test_RFC7520_Section_5_8() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_151)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .a128KW,
                encryptionAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
            04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("aY5_Ghmk9KxWPBLu_glx1w"),
            initializationVector: Base64URL.decode("Qx0pmsDa8KnJc9Jo")
        )

        let expectedSerialization = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
        .
        CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx
        .
        Qx0pmsDa8KnJc9Jo
        .
        AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6
        1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe
        F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE
        wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p
        uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa
        a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF
        .
        ER7MWJZ1FBI_NKvn7Zb1Lw
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.9
    func test_RFC7520_Section_5_9() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_151)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .a128KW,
                encryptionAlgorithm: .a128GCM,
                compressionAlgorithm: .deflate,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
            04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("hC-MpLZSuwWv8sexS6ydfw"),
            initializationVector: Base64URL.decode("p9pUq6XHY0jfEZIl")
        )

        let expectedSerialization = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0
        .
        5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi
        .
        p9pUq6XHY0jfEZIl
        .
        HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyez
        SPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0
        m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBK
        hpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw
        .
        VILuUwuIxaLVmh5X-T7kmA
        """.replacingWhiteSpacesAndNewLines()

        XCTAssertEqual(serialization, expectedSerialization)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.10
    func test_RFC7520_Section_5_10() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_151)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(
                algorithm: .a128KW,
                encryptionAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
            04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
            """.replacingWhiteSpacesAndNewLines(),
            contentEncryptionKey: Base64URL.decode("75m1ALsYv10pZTKPWrsqdg"),
            initializationVector: Base64URL.decode("veCx9ece2orS7c_N"),
            additionalAuthenticatedData: Base64URL.decode("""
            WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fS
            widGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0Iixb
            IkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LC
            J0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d
            """.replacingWhiteSpacesAndNewLines()),
            jsonEncoder: .init()
        )

        let expectedSerialization = """
        {
          "recipients": [
            {
              "encrypted_key": "4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X"
            }
          ],
          "protected": "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04Mz
              MyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn
              0",
          "iv": "veCx9ece2orS7c_N",
          "aad": "WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxb
              ImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4i
              LHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIs
              IiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVy
              Iix7fSwidGV4dCIsIk0iXV1d",
          "ciphertext": "Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0
              Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14
              T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fz
              OI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrs
              LNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy
              2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3
              X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV",
          "tag": "vOaH_Rajnpy_3hOtqvZHRA"
        }
        """.replacingWhiteSpacesAndNewLines()

        let jsonObject = try JSONSerialization.jsonObject(with: expectedSerialization.data(using: .utf8)!)
        let computedJSONObject = try JSONSerialization.jsonObject(with: serialization.data(using: .utf8)!)
        XCTAssertEqual(jsonObject as! NSDictionary, computedJSONObject as! NSDictionary)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.11
    func test_RFC7520_Section_5_11() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_151)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            protectedHeader: .init(encryptionAlgorithm: .a128GCM),
            encodedProtectedHeader: "eyJlbmMiOiJBMTI4R0NNIn0",
            sharedUnprotectedHeader: .init(
                algorithm: .a128KW,
                keyID: "81b20965-8332-43d9-a468-82160ad91ac8"
            ),
            contentEncryptionKey: Base64URL.decode("WDgEptBmQs9ouUvArz6x6g"),
            initializationVector: Base64URL.decode("WgEJsDS9bkoXQ3nR"),
            jsonEncoder: .init()
        )

        let expectedSerialization = """
        {
          "recipients": [
            {
              "encrypted_key": "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"
            }
          ],
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8"
          },
          "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
          "iv": "WgEJsDS9bkoXQ3nR",
          "ciphertext": "lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2D
              M3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9O
              CCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6
              uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5
              g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU
              4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3
              HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",
          "tag": "fNYLqpUe84KD45lvDiaBAQ"
        }
        """.replacingWhiteSpacesAndNewLines()

        let jsonObject = try JSONSerialization.jsonObject(with: expectedSerialization.data(using: .utf8)!)
        let computedJSONObject = try JSONSerialization.jsonObject(with: serialization.data(using: .utf8)!)
        XCTAssertEqual(jsonObject as! NSDictionary, computedJSONObject as! NSDictionary)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.12
    func test_RFC7520_Section_5_12() throws {
        let plaintext = rfc7520_figure_72

        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_151)

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            sharedUnprotectedHeader: .init(
                algorithm: .a128KW,
                encryptionAlgorithm: .a128GCM,
                keyID: "81b20965-8332-43d9-a468-82160ad91ac8"
            ),
            contentEncryptionKey: Base64URL.decode("KBooAFl30QPV3vkcZlXnzQ"),
            initializationVector: Base64URL.decode("YihBoVOGsR1l7jCD"),
            jsonEncoder: .init()
        )

        let expectedSerialization = """
        {
          "recipients": [
            {
              "encrypted_key": "244YHfO_W7RMpQW81UjQrZcq5LSyqiPv"
            }
          ],
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
            "enc": "A128GCM"
          },
          "iv": "YihBoVOGsR1l7jCD",
          "ciphertext": "qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-
              arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHF
              SP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDs
              RPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8
              ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDf
              rb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4
              -8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF",
          "tag": "e2m0Vm7JvjK2VpCKXS-kyg"
        }
        """.replacingWhiteSpacesAndNewLines()

        let jsonObject = try JSONSerialization.jsonObject(with: expectedSerialization.data(using: .utf8)!)
        let computedJSONObject = try JSONSerialization.jsonObject(with: serialization.data(using: .utf8)!)
        XCTAssertEqual(jsonObject as! NSDictionary, computedJSONObject as! NSDictionary)

        let receivedPlaintext = try JWE.decrypt(serialization: serialization, using: recipientJWK)

        XCTAssertEqual(plaintext, receivedPlaintext)
    }

    // See https://www.rfc-editor.org/rfc/rfc7520#section-5.13
    func test_RFC7520_Section_5_13() throws {
        let plaintext = rfc7520_figure_72

        let recipient1JWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_73)
        let recipient2JWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_108)
        let recipient3JWK = try JSONDecoder().decode(JWK.self, from: rfc7520_figure_138)

        let recipients: [JWE.Recipient] = try [
            .init(
                header: .init(
                    algorithm: .rsa1_5,
                    keyID: "frodo.baggins@hobbiton.example"
                ),
                jwk: recipient1JWK
            ),
            try .init(
                header: .init(
                    algorithm: .ecdhESA256KW,
                    keyID: "peregrin.took@tuckborough.example",
                    ephemeralPublicKey: JSONDecoder().decode(
                        JWK.self,
                        from: """
                        {
                          "kty": "EC",
                          "crv": "P-384",
                          "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2Dt
                              MRb25Ma2CX",
                          "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw9
                              1fzZ84pbfm",
                          "d": "1DKHfTv-PiifVw2VBHM_ZiVcwOMxkOyANS_lQHJcrDxVY3jhVCvZPw
                              MxJKIE793C"
                        }
                        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                    )
                ),
                jwk: recipient2JWK
            ),
            .init(
                header: .init(
                    algorithm: .a256GCMKW,
                    keyID: "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                    initializationVector: Base64URL.decode("AvpeoPZ9Ncn9mkBn"),
                    authenticationTag: Base64URL.decode("59Nqh1LlYtVIhfD3pgRGvw")
                ),
                jwk: recipient3JWK
            ),
        ]

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipients,
            protectedHeader: .init(encryptionAlgorithm: .a128CBCHS256),
            encodedProtectedHeader: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            sharedUnprotectedHeader: .init(contentType: "text/plain"),
            contentEncryptionKey: Base64URL.decode("zXayeJ4gvm8NJr3IUInyokTUO-LbQNKEhe_zWlYbdpQ"),
            initializationVector: Base64URL.decode("VgEIHY20EnzUtZFl2RpB1g"),
            jsonEncoder: .init()
        )

        // Note: Due to 'RSA1_5' encryption's non-deterministic nature, serialization won't match the [test vector](https://www.rfc-editor.org/rfc/rfc7520#section-5.13.7)
        // However, successful decryption remains essential.

        let receivedPlaintext = try JWE.decrypt(
            serialization: serialization,
            using: [
                recipient1JWK,
                recipient2JWK,
                recipient3JWK,
            ]
        )

        XCTAssertEqual(plaintext, receivedPlaintext)

        let receivedPlaintextTestVector = try JWE.decrypt(
            serialization: """
            {
              "recipients": [
                {
                  "encrypted_key": "dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zj
                      wj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-
                      vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076
                      DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S
                      1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbe
                      YSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n
                      5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ",
                  "header": {
                    "alg": "RSA1_5",
                    "kid": "frodo.baggins@hobbiton.example"
                  }
                },
                {
                  "encrypted_key": "ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHi
                      xJuw_elY4gSSId_w",
                  "header": {
                    "alg": "ECDH-ES+A256KW",
                    "kid": "peregrin.took@tuckborough.example",
                    "epk": {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhs
                          E2xAn2DtMRb25Ma2CX",
                      "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEj
                          I1pOMbw91fzZ84pbfm"
                    }
                  }
                },
                {
                  "encrypted_key": "a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-Wy
                      TpS1E",
                  "header": {
                    "alg": "A256GCMKW",
                    "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                    "tag": "59Nqh1LlYtVIhfD3pgRGvw",
                    "iv": "AvpeoPZ9Ncn9mkBn"
                  }
                }
              ],
              "unprotected": {
                "cty": "text/plain"
              },
              "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
              "iv": "VgEIHY20EnzUtZFl2RpB1g",
              "ciphertext": "ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK
                  04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM
                  9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSa
                  P6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7p
                  kt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQ
                  rgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3
                  ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLCht
                  azE",
              "tag": "BESYyFN7T09KY7i8zKs5_g"
            }
            """.replacingWhiteSpacesAndNewLines(),
            using: [
                recipient1JWK,
                recipient2JWK,
                recipient3JWK,
            ]
        )

        XCTAssertEqual(plaintext, receivedPlaintextTestVector)
    }

    func test_ECDH_1PU_A256GCM() throws {
        let plaintext = "Hello, World!".data(using: .utf8)!

        // Obtain the recipient's key (for example, by fetching it from a widely recognized URL).
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "61F56896-F537-43B0-B0FA-573E5C0F66A3",
                 "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw"}
            """.data(using: .utf8)!
        )

        // Obtain the sender's key (for example, by fetching it from the local key store).
        // Important: The key type and curve must match the recipient's key.
        let senderJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "3EA04AE5-FC22-4F99-9250-28EB7492CCF5",
                 "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                 "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}
            """.data(using: .utf8)!
        )

        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientJWK,
            from: senderJWK,
            protectedHeader: .init(
                algorithm: .ecdh1PU,
                encryptionAlgorithm: .a256GCM,
                compressionAlgorithm: .deflate,
                // Inform the recipient about the specific private key to use for decryption.
                keyID: recipientJWK.keyID,
                // Specify the ephemeral public key for consistent output. Leave it empty to let the library generate it automatically.
                ephemeralPublicKey: JSONDecoder().decode(
                    JWK.self,
                    from: """
                          {"kty": "OKP",
                           "crv": "X25519",
                           "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
                           "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}
                    """.data(using: .utf8)!
                ),
                // Inform the recipient about the location to retrieve the sender's keys.
                agreementPartyUInfo: "https://example.com/sender.jwks".data(using: .ascii) ?? .init(),
                // Inform the recipient about the specific sender key used for encrypted authentication.
                senderKeyID: senderJWK.keyID
            ),
            encodedProtectedHeader: """
            eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC0xUFUiLCJza2lkIjoiM0VBMDRBRTUtRkMyMi00Rjk5LTkyNTAtMjhFQjc0OTJDQ0Y1IiwiemlwIjoiREVGIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn0sImtpZCI6IjYxRjU2ODk2LUY1MzctNDNCMC1CMEZBLTU3M0U1QzBGNjZBMyIsImFwdSI6ImFIUjBjSE02THk5bGVHRnRjR3hsTG1OdmJTOXpaVzVrWlhJdWFuZHJjdyJ9
            """.replacingWhiteSpacesAndNewLines(),
            // Specify the initialization vector for consistent output. Leave it empty to let the library generate it automatically.
            initializationVector: Base64URL.decode("FkGX4uU1mkcLCWV9")
        )

        let expectedSerialization = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC0xUFUiLCJza2lkIjoiM0VBMDRBRTUtRkMyMi00Rjk5LTkyNTAtMjhFQjc0OTJDQ0Y1IiwiemlwIjoiREVGIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn0sImtpZCI6IjYxRjU2ODk2LUY1MzctNDNCMC1CMEZBLTU3M0U1QzBGNjZBMyIsImFwdSI6ImFIUjBjSE02THk5bGVHRnRjR3hsTG1OdmJTOXpaVzVrWlhJdWFuZHJjdyJ9..FkGX4uU1mkcLCWV9.Mew3l2P-_J01i0Y-qT1A.fdFpw6tGmMV4RXAGN74hwA"

        XCTAssertEqual(serialization, expectedSerialization)

        let jwe = try JWE(compactSerialization: expectedSerialization)

        // Obtain the recipient's key mentioned in the JOSE header (for example, by fetching it from the local key store).
        let recipientPrivateJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "61F56896-F537-43B0-B0FA-573E5C0F66A3",
                 "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                 "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}
            """.data(using: .utf8)!
        )
        XCTAssertEqual(recipientPrivateJWK.keyID, jwe.protectedHeader?.keyID)

        // Obtain the sender's key referenced by the 'apu' JOSE header parameter value (for example, by fetching it from a widely recognized URL).
        guard
            let agreementPartyUInfo = jwe.protectedHeader?.agreementPartyUInfo,
            let agreementPartyUInfoURLString = String(data: agreementPartyUInfo, encoding: .ascii),
            let _ = URL(string: agreementPartyUInfoURLString)
        else {
            XCTFail("Unable to retrieve sender key")
            return
        }

        let senderPublicJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "3EA04AE5-FC22-4F99-9250-28EB7492CCF5",
                 "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4"}
            """.data(using: .utf8)!
        )

        XCTAssertEqual(senderPublicJWK.keyID, jwe.protectedHeader?.senderKeyID)

        let receivedPlaintext = try jwe.decrypt(using: recipientPrivateJWK, from: senderPublicJWK)

        XCTAssertEqual(receivedPlaintext, plaintext)
    }

    func test_ECDH_RoundTrip() throws {
        let keys: [(JWK, JWK)] = try [
            (P256.KeyAgreement.PrivateKey().jwkRepresentation, P256.KeyAgreement.PrivateKey().jwkRepresentation),
            (P384.KeyAgreement.PrivateKey().jwkRepresentation, P384.KeyAgreement.PrivateKey().jwkRepresentation),
            (P521.KeyAgreement.PrivateKey().jwkRepresentation, P521.KeyAgreement.PrivateKey().jwkRepresentation),
            (Curve25519.KeyAgreement.PrivateKey().jwkRepresentation, Curve25519.KeyAgreement.PrivateKey().jwkRepresentation),
            (Curve448.KeyAgreement.PrivateKey().jwkRepresentation, Curve448.KeyAgreement.PrivateKey().jwkRepresentation),
            (secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation, secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation),
        ]
        let plaintexts: [Data] = [
            .init(),
            "Hello, World!".data(using: .utf8)!,
            Data([UInt8](repeating: 0, count: 1024)),
            .random(count: 1024),
        ]
        let algorithms: [JOSEHeader.KeyManagementAlgorithm] = [
            .ecdh1PU, .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW, .ecdh1PUA128KW, .ecdh1PUA192KW, .ecdh1PUA256KW,
        ]
        let contentEncryptionAlgoritms: [JOSEHeader.ContentEncryptionAlgorithm] = JOSEHeader.ContentEncryptionAlgorithm.allCases
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .withoutEscapingSlashes

        for (recipientKey, senderKey) in keys {
            for plaintext in plaintexts {
                for algorithm in algorithms {
                    for encryptionAlgorithm in contentEncryptionAlgoritms {
                        for compressionAlgorithm in [JOSEHeader.CompressionAlgorithm.deflate, nil] {
                            for jsonEncoder in [jsonEncoder, nil] {
                                if !encryptionAlgorithm.canBeAESKeyWrapped() {
                                    continue
                                }
                                let receivedPlaintext = try roundTrip(
                                    plaintext: plaintext,
                                    recipientKey: recipientKey,
                                    senderKey: senderKey,
                                    algorithm: algorithm,
                                    encryptionAlgorithm: encryptionAlgorithm,
                                    compressionAlgorithm: compressionAlgorithm,
                                    jsonEncoder: jsonEncoder
                                )
                                XCTAssertEqual(plaintext, receivedPlaintext)
                            }
                        }
                    }
                }
            }
        }
    }

    private func roundTrip(
        plaintext: Data,
        recipientKey: JWK,
        senderKey: JWK,
        algorithm: JOSEHeader.KeyManagementAlgorithm,
        encryptionAlgorithm: JOSEHeader.ContentEncryptionAlgorithm,
        compressionAlgorithm: JOSEHeader.CompressionAlgorithm?,
        jsonEncoder: JSONEncoder?
    ) throws -> Data {
        let serialization = try JWE.encrypt(
            plaintext: plaintext,
            to: recipientKey,
            from: senderKey,
            protectedHeader: .init(
                algorithm: algorithm,
                encryptionAlgorithm: encryptionAlgorithm,
                compressionAlgorithm: compressionAlgorithm
            ),
            jsonEncoder: jsonEncoder
        )
        let receivedPlaintext = try JWE.decrypt(
            serialization: serialization,
            using: recipientKey,
            from: senderKey.publicKey
        )
        return receivedPlaintext
    }
}
