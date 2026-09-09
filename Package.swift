// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "awseal",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        // Already an AWS SDK dependency; use its no-op handler to keep SDK logs off stdout/stderr.
        .package(url: "https://github.com/apple/swift-log", from: "1.6.4"),
        .package(url: "https://github.com/awslabs/aws-sdk-swift", from: "1.5.32")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .executableTarget(
            name: "awseal",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "AWSSSO", package: "aws-sdk-swift"),
                .product(name: "AWSSSOOIDC", package: "aws-sdk-swift")
            ]
        ),
        .testTarget(name: "AwsealTests", dependencies: ["awseal"]),
    ]
)
