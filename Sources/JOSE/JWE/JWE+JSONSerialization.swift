// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

public extension JWE {
    /// Serializes the JWE object into a JSON string using the provided JSON encoder.
    ///
    /// - Parameter encoder: A JSONEncoder object used for encoding the JWE object. Defaults to a new JSONEncoder instance.
    /// - Returns: A JSON string representation of the JWE object.
    /// - Throws: An EncodingError if the JWE object cannot be serialized into a JSON string.
    func jsonSerialization(_ encoder: JSONEncoder = .init()) throws -> String {
        return try String(data: encoder.encode(self), encoding: .utf8) ?? ""
    }

    /// Initializes a JWE object from a JSON serialization string.
    ///
    /// - Parameter jsonSerialization: A JSON serialization string representation of a JWE object.
    /// - Throws: A DecodingError if the provided string cannot be deserialized into a JWE object.
    init(jsonSerialization: String) throws {
        let data = jsonSerialization.data(using: .utf8) ?? .init()
        try self.init(jsonSerialization: data)
    }

    /// Initializes a JWE object from a JSON serialization data.
    ///
    /// - Parameter jsonSerialization: A JSON serialization data representation of a JWE object.
    /// - Throws: A DecodingError if the provided data cannot be deserialized into a JWE object.
    init(jsonSerialization: Data) throws {
        self = try JSONDecoder().decode(JWE.self, from: jsonSerialization)
    }
}

extension JWE: Codable {
    enum CodingKeys: String, CodingKey {
        case protected, unprotected, recipients, aad, iv, ciphertext, tag
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(getEncodedProtectedHeader(), forKey: .protected)
        try container.encodeIfPresent(sharedUnprotectedHeader, forKey: .unprotected)
        try container.encodeIfPresent(recipients, forKey: .recipients)
        if let aad = additionalAuthenticatedData {
            try container.encode(Base64URL.encode(aad), forKey: .aad)
        }
        try container.encode(Base64URL.encode(initializationVector ?? .init()), forKey: .iv)
        try container.encode(Base64URL.encode(ciphertext ?? .init()), forKey: .ciphertext)
        try container.encode(Base64URL.encode(authenticationTag ?? .init()), forKey: .tag)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let encodedProtectedHeader = try container.decodeIfPresent(String.self, forKey: .protected)
        let sharedUnprotectedHeader = try container.decodeIfPresent(JOSEHeader.self, forKey: .unprotected)
        let recipients = try container.decodeIfPresent([Recipient].self, forKey: .recipients)
        var initializationVector: Data?
        if let value = try container.decodeIfPresent(String.self, forKey: .iv) {
            initializationVector = try Base64URL.decode(value)
        }
        var ciphertext: Data?
        if let value = try container.decodeIfPresent(String.self, forKey: .ciphertext) {
            ciphertext = try Base64URL.decode(value)
        }
        var authenticationTag: Data?
        if let value = try container.decodeIfPresent(String.self, forKey: .tag) {
            authenticationTag = try Base64URL.decode(value)
        }
        var additionalAuthenticatedData: Data?
        if let value = try container.decodeIfPresent(String.self, forKey: .aad) {
            additionalAuthenticatedData = try Base64URL.decode(value)
        }
        try self.init(
            encodedProtectedHeader: encodedProtectedHeader,
            sharedUnprotectedHeader: sharedUnprotectedHeader,
            recipients: recipients,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
    }
}
