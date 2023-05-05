// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

public extension JWE {
    /// Represents a JWE recipient.
    ///
    /// This struct contains the necessary information for each recipient of a JWE message,
    /// including the per-recipient unprotected header, the public key of the recipient, and the encrypted key.
    /// The recipient's public key (`jwk`) is used for generating the encrypted key.
    struct Recipient: Hashable {
        /// The per-recipient unprotected header.
        public var header: JOSEHeader?

        /// The public key of the recipient, used for generating the encrypted key.
        public var jwk: JWK?

        /// The encrypted key.
        public var encryptedKey: Data?

        /// Initializes a new `Recipient` with the given parameters.
        ///
        /// - Parameters:
        ///   - header: The per-recipient unprotected header.
        ///   - jwk: The public key of the recipient, used for generating the encrypted key.
        ///   - encryptedKey: The encrypted key.
        public init(
            header: JOSEHeader? = nil,
            jwk: JWK? = nil,
            encryptedKey: Data? = nil
        ) {
            self.header = header
            self.jwk = jwk
            self.encryptedKey = encryptedKey
        }
    }
}

extension JWE.Recipient: Codable {
    enum CodingKeys: String, CodingKey {
        case header
        case encryptedKey = "encrypted_key"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(header, forKey: .header)
        if let value = encryptedKey {
            try container.encode(Base64URL.encode(value), forKey: .encryptedKey)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let value = try container.decodeIfPresent(JOSEHeader.self, forKey: .header) {
            header = value
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .encryptedKey) {
            encryptedKey = try Base64URL.decode(value)
        }
    }
}
