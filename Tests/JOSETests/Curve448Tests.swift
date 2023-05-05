// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoSwift
@testable import JOSE
import XCTest

final class Curve448Tests: XCTestCase {
    // See https://www.rfc-editor.org/rfc/rfc7748#section-6.2
    func test_RFC7748_6_2() throws {
        let alicePrivateKeyHexString = """
        9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d
        d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b
        """.replacingWhiteSpacesAndNewLines()

        let bobPrivateKeyHexString = """
        1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d
        6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d
        """.replacingWhiteSpacesAndNewLines()

        let alicePrivateKey = try Curve448.KeyAgreement.PrivateKey(
            rawRepresentation: Data(hex: alicePrivateKeyHexString)
        )

        let bobsPrivateKey = try Curve448.KeyAgreement.PrivateKey(
            rawRepresentation: Data(hex: bobPrivateKeyHexString)
        )
        let bobsPublicKey = bobsPrivateKey.publicKey

        XCTAssertEqual(
            alicePrivateKey.publicKey.rawRepresentation.toHexString(),
            """
            9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c
            22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
            """.replacingWhiteSpacesAndNewLines()
        )

        XCTAssertEqual(
            bobsPublicKey.rawRepresentation.toHexString(),
            """
            3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430
            27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609
            """.replacingWhiteSpacesAndNewLines()
        )

        let sharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobsPublicKey)

        XCTAssertEqual(
            sharedSecret,
            Data(
                hex: """
                07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b
                b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d
                """.replacingWhiteSpacesAndNewLines()
            )
        )
    }
}
