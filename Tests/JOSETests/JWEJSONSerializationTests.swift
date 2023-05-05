// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
@testable import JOSE
import XCTest

final class JWEJSONSerializationTests: XCTestCase {
    // See https://www.rfc-editor.org/rfc/rfc7516#appendix-A.4.7
    func test_RFC7516_Appendix_A_4_7() throws {
        let jsonSerialization = """
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
        """.replacingWhiteSpacesAndNewLines()

        let jwe = try JWE(jsonSerialization: jsonSerialization)

        XCTAssertEqual(
            try jwe.getEncodedProtectedHeader(),
            "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
        )
        XCTAssertEqual(jwe.sharedUnprotectedHeader?.jwkSetURL, "https://server.example.com/keys.jwks")
        XCTAssertEqual(jwe.recipients?.count, 2)
        XCTAssertEqual(jwe.recipients?[0].header?.algorithm, .rsa1_5)
        XCTAssertEqual(jwe.recipients?[0].header?.keyID, "2011-04-29")
        XCTAssertEqual(jwe.recipients?[0].encryptedKey, try Base64URL.decode("""
        UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
        kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
        GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
        YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
        cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
        wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A
        """.replacingWhiteSpacesAndNewLines()))
        XCTAssertEqual(jwe.recipients?[1].header?.algorithm, .a128KW)
        XCTAssertEqual(jwe.recipients?[1].header?.keyID, "7")
        XCTAssertEqual(
            jwe.recipients?[1].encryptedKey,
            try Base64URL.decode("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ")
        )
        XCTAssertEqual(
            jwe.initializationVector,
            try Base64URL.decode("AxY8DCtDaGlsbGljb3RoZQ")
        )
        XCTAssertEqual(
            jwe.ciphertext,
            try Base64URL.decode("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY")
        )
        XCTAssertEqual(
            jwe.authenticationTag,
            try Base64URL.decode("Mz-VPPyU4RlcuYv1IwIvzw")
        )

        // Decode
        let jsonObject = try JSONSerialization.jsonObject(with: jsonSerialization.data(using: .utf8)!)
        let computedJSONObject = try JSONSerialization.jsonObject(with: jwe.jsonSerialization().data(using: .utf8)!)
        XCTAssertEqual(jsonObject as! NSDictionary, computedJSONObject as! NSDictionary)
    }
}
