// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

public extension JWE {
    /// Initializes a new JWE object by parsing the compact serialization string.
    ///
    /// The compact serialization format represents the JWE object as a sequence of five Base64URL-encoded strings separated by period ('.') characters, in the following order:
    /// 1. the Base64URL-encoded protected header
    /// 2. the Base64URL-encoded encrypted key
    /// 3. the Base64URL-encoded initialization vector
    /// 4. the Base64URL-encoded ciphertext
    /// 5. the Base64URL-encoded authentication tag
    ///
    /// - Parameters:
    ///   - compactSerialization: The compact serialization string representing the JWE object.
    /// - Throws:
    ///   `JWE.Error.invalidNumberOfSegments` if the number of segments in the compact serialization string is not 5, or `Base64URLError` if any of the Base64URL-encoded strings are not valid.
    init(compactSerialization: String) throws {
        let components = compactSerialization.components(separatedBy: ".")

        guard components.count == 5 else {
            throw JWE.Error.invalidNumberOfSegments(components.count)
        }

        try self.init(
            encodedProtectedHeader: components[0],
            encryptedKey: Base64URL.decode(components[1]),
            initializationVector: Base64URL.decode(components[2]),
            ciphertext: Base64URL.decode(components[3]),
            authenticationTag: Base64URL.decode(components[4])
        )
    }

    /// The JWE compact serialization of the JWE object.
    ///
    /// The compact serialization format represents the JWE object as a sequence of five Base64URL-encoded strings separated by period ('.') characters, in the following order:
    ///
    /// 1. the Base64URL-encoded protected header
    /// 2. the Base64URL-encoded encrypted key
    /// 3. the Base64URL-encoded initialization vector
    /// 4. the Base64URL-encoded ciphertext
    /// 5. the Base64URL-encoded authentication tag
    func compactSerialization() throws -> String {
        let compactSerialization = try [
            getEncodedProtectedHeader() ?? "",
            Base64URL.encode(recipients?.first?.encryptedKey ?? .init()),
            Base64URL.encode(initializationVector ?? .init()),
            Base64URL.encode(ciphertext ?? .init()),
            Base64URL.encode(authenticationTag ?? .init()),
        ].joined(separator: ".")

        return compactSerialization
    }
}
