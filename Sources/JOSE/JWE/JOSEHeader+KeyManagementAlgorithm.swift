// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

public extension JOSEHeader {
    /// Supported JWE cryptographic algorithms for key management.
    ///
    /// For more information, see [RFC7518 Section 4.1](https://www.rfc-editor.org/rfc/rfc7518#section-4.1)
    enum KeyManagementAlgorithm: String, Codable, Equatable, CaseIterable, Hashable {
        case rsa1_5 = "RSA1_5"
        case rsaOAEP = "RSA-OAEP"
        case rsaOAEP256 = "RSA-OAEP-256"
        case a128KW = "A128KW"
        case a192KW = "A192KW"
        case a256KW = "A256KW"
        case direct = "dir"
        case ecdhES = "ECDH-ES"
        case ecdhESA128KW = "ECDH-ES+A128KW"
        case ecdhESA192KW = "ECDH-ES+A192KW"
        case ecdhESA256KW = "ECDH-ES+A256KW"
        case a128GCMKW = "A128GCMKW"
        case a192GCMKW = "A192GCMKW"
        case a256GCMKW = "A256GCMKW"
        case pbes2HS256A128KW = "PBES2-HS256+A128KW"
        case pbes2HS384A192KW = "PBES2-HS384+A192KW"
        case pbes2HS512A256KW = "PBES2-HS512+A256KW"
        // See [ECDH-1PU Draft](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
        case ecdh1PU = "ECDH-1PU"
        case ecdh1PUA128KW = "ECDH-1PU+A128KW"
        case ecdh1PUA192KW = "ECDH-1PU+A192KW"
        case ecdh1PUA256KW = "ECDH-1PU+A256KW"
    }

    /// A method of determining the Content Encryption Key value to use. Each algorithm used for determining the CEK value uses a specific Key Management Mode.
    enum KeyManagementMode {
        /// A Key Management Mode in which the CEK value is encrypted to the intended recipient using an asymmetric encryption algorithm.
        case keyEncryption
        /// A Key Management Mode in which the CEK value is encrypted to the intended recipient using a symmetric key wrapping algorithm.
        case keyWrapping
        /// A Key Management Mode in which a key agreement algorithm is used to agree upon the CEK value.
        case directKeyAgreement
        /// A Key Management Mode in which a key agreement algorithm is used to agree upon a symmetric key used to encrypt the CEK value to the intended recipient using a symmetric key wrapping algorithm.
        case keyAgreementWithKeyWrapping
        /// A Key Management Mode in which the CEK value used is the secret symmetric key value shared between the parties.
        case directEncryption
    }
}

public extension JOSEHeader.KeyManagementAlgorithm {
    /// Returns the key management mode of this algorithm.
    var mode: JOSEHeader.KeyManagementMode {
        switch self {
        case .rsa1_5, .rsaOAEP, .rsaOAEP256, .pbes2HS256A128KW, .pbes2HS384A192KW, .pbes2HS512A256KW:
            return .keyEncryption
        case .a128KW, .a192KW, .a256KW, .a128GCMKW, .a192GCMKW, .a256GCMKW:
            return .keyWrapping
        case .direct:
            return .directEncryption
        case .ecdhES, .ecdh1PU:
            return .directKeyAgreement
        case .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW, .ecdh1PUA128KW, .ecdh1PUA192KW, .ecdh1PUA256KW:
            return .keyAgreementWithKeyWrapping
        }
    }

    /// Returns a Boolean value indicating whether this algorithm uses AES key wrapping.
    var usesAESKeyWrapping: Bool {
        rawValue.hasSuffix("A128KW") ||
            rawValue.hasSuffix("A192KW") ||
            rawValue.hasSuffix("A256KW")
    }

    /// Returns a Boolean value indicating whether this algorithm uses AES-GCM key wrapping.
    var usesAESGCMKeyWrapping: Bool {
        rawValue.hasSuffix("GCMKW")
    }

    /// Returns a Boolean value indicating whether this algorithm uses RSA key encryption.
    var usesRSAKeyEncryption: Bool {
        rawValue.hasPrefix("RSA")
    }

    /// Returns a Boolean value indicating whether this algorithm uses PBES2 key encryption.
    var usesPBES2KeyEncryption: Bool {
        rawValue.hasPrefix("PBES2")
    }
}
