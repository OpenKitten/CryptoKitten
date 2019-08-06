// swift-tools-version:4.0
import PackageDescription

var package = Package(
    name: "CryptoKitten",
    products: [
        .library(name: "CryptoKitten", targets: ["CryptoKitten"])
    ],
    targets: [
        .target(name: "CryptoKitten")
    ]
)
