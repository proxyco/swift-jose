// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoSwift
import Foundation

public extension JOSEHeader {
    /// Supported JWE cryptographic algorithms for content encryption.
    ///
    /// For more information, see [RFC7518 Section 5.1](https://www.rfc-editor.org/rfc/rfc7518#section-5.1)
    enum ContentEncryptionAlgorithm: String, Codable, Equatable, CaseIterable, Hashable {
        case a128CBCHS256 = "A128CBC-HS256"
        case a192CBCHS384 = "A192CBC-HS384"
        case a256CBCHS512 = "A256CBC-HS512"
        case a128GCM = "A128GCM"
        case a192GCM = "A192GCM"
        case a256GCM = "A256GCM"
    }
}

extension JOSEHeader.ContentEncryptionAlgorithm {
    /// Returns the key size in bits.
    var keySizeInBits: Int {
        switch self {
        case .a128GCM: return 128
        case .a192GCM: return 192
        case .a256GCM: return 256
        case .a128CBCHS256: return 256
        case .a192CBCHS384: return 384
        case .a256CBCHS512: return 512
        }
    }

    /// Returns the initialization vector size in bits.
    var initializationVectorSizeInBits: Int {
        switch self {
        case .a128CBCHS256, .a192CBCHS384, .a256CBCHS512: return 128
        case .a128GCM, .a192GCM, .a256GCM: return 96
        }
    }

    /// Determines if the key used in the encryption algorithm can be AES key wrapped.
    func canBeAESKeyWrapped() -> Bool {
        // See https://www.rfc-editor.org/rfc/rfc3394#section-2:
        // "Before being wrapped, the key data is parsed into n blocks of 64 bits. The only restriction the key wrap algorithm places on n is that n be at least two."
        // However, CryptoKit.AES.KeyWrap throws error for keys larger that 256 bits.
        return keySizeInBits <= 256
    }
}
