// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JOSE",
    platforms: [
        .macOS(.v12), .iOS(.v15),
    ],
    products: [
        .library(
            name: "swift-jose",
            targets: ["JOSE"]
        ),
    ],
    dependencies: [
        // For `X448` support
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "1.1.180")),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMajor(from: "0.10.0")),
        // For `AES_CBC_HMAC_SHA2`, `PBES2` and RSA DER encoding support
        // Note: This package will be modified once the pull request at https://github.com/krzyzanowskim/CryptoSwift/pull/1014 is merged and released under a tag.
        .package(url: "https://github.com/proxyco/CryptoSwift.git", revision: "8c8aff8daaf4581ff0d86926b3d51e7537462143"),
        // .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.7.1")),
    ],
    targets: [
        .target(
            name: "JOSE",
            dependencies: [
                "OpenSSL",
                .product(name: "secp256k1", package: "secp256k1.swift"),
                "CryptoSwift",
            ]
        ),
        .testTarget(
            name: "JOSETests",
            dependencies: ["JOSE"]
        ),
    ]
)
