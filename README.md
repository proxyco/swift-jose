# Swift JOSE

Swift JOSE is a package for the Swift programming language that provides implementation for the JSON Object Signing and Encryption (JOSE) family of [specifications](https://datatracker.ietf.org/wg/jose/documents/).

## Overview

- JSON Web Signature (JWS) [RFC7515](https://www.rfc-editor.org/rfc/rfc7515)
- JSON Web Encryption (JWE) [RFC7516](https://www.rfc-editor.org/rfc/rfc7516)
- JSON Web Key (JWK) [RFC7517](https://www.rfc-editor.org/rfc/rfc7517)
- JSON Web Algorithms (JWA) [RFC7518](https://www.rfc-editor.org/rfc/rfc7518)
- JSON Web Key (JWK) Thumbprint [RFC7638](https://www.rfc-editor.org/rfc/rfc7638)
- CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE) [RFC8037](https://www.rfc-editor.org/rfc/rfc8037)
- CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms [RFC8812](https://www.rfc-editor.org/rfc/rfc8812)
- Public Key Authenticated Encryption for JOSE: ECDH-1PU [draft-madden-jose-ecdh-1pu-04](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)

> **Note**
> The code related to signatures from the above specifications is still a work in progress. PRs are welcome.

## Supported Swift Versions

This library supports Swift 5.7 or later and will support the latest stable Swift version and the two versions prior.

## Getting Started

To use Swift JOSE, add the following dependency to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/proxyco/swift-jose.git", upToNextMinor(from: "0.1.0"))
]
```

Note that this repository does not have a 1.0 tag yet, so the API is not stable.

Then, add the specific product dependency to your target:

```swift
dependencies: [
    .product(name: "JOSE", package: "swift-jose"),
]
```

## Package Dependencies

Swift JOSE has the following package dependencies:

- [OpenSSL](https://github.com/krzyzanowskim/OpenSSL.git): For `X448` support.
- [secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift.git): For `secp256k1` support.
- [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift.git): For `AES_CBC_HMAC_SHA2`, `PBES2`, and RSA DER encoding support.

## Usage

### JWE Example

```swift
// Generate recipient key pair
let recipientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
let recipientPublicKey = recipientPrivateKey.publicKey

// Encrypt plaintext using JWE
let plaintext = "Hello, World!".data(using: .utf8)!
let serialization = try JWE.encrypt(
    plaintext: plaintext,
    to: recipientPublicKey.jwkRepresentation,
    protectedHeader: .init(
        algorithm: .ecdhESA256KW,
        encryptionAlgorithm: .a256GCM,
        compressionAlgorithm: .deflate
    )
)
// Sender sends JWE serialization to recipient...
// ...

// Decrypt ciphertext
let receivedPlaintext = try JWE.decrypt(
    serialization: serialization,
    using: recipientPrivateKey.jwkRepresentation
)
```

For more information on how to use Swift JOSE, please refer to the [documentation](https://swiftpackageindex.com/proxyco/swift-jose/documentation).
