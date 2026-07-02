# Swift RFC 7617

[![CI](https://github.com/swift-ietf/swift-rfc-7617/workflows/CI/badge.svg)](https://github.com/swift-ietf/swift-rfc-7617/actions/workflows/ci.yml)
![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Swift implementation of RFC 7617: The 'Basic' HTTP Authentication Scheme.

## Overview

RFC 7617 defines the "Basic" HTTP authentication scheme, which transmits credentials as user-id/password pairs, encoded using Base64. This package provides a pure Swift implementation of both the client-side credential generation and the server-side challenge mechanism according to the specification.

The package handles credential encoding/decoding, Authorization header generation/parsing, and WWW-Authenticate challenge creation/parsing with full support for UTF-8 encoding as specified in RFC 7617.

## Features

- **Credential Management**: Create and validate HTTP Basic authentication credentials
- **Base64 Encoding**: Automatic Base64 encoding of username:password pairs
- **Header Generation**: Generate compliant Authorization and WWW-Authenticate headers
- **Header Parsing**: Parse and validate authentication headers from HTTP requests/responses
- **UTF-8 Support**: Full support for UTF-8 encoded credentials as per RFC specification
- **Type-Safe API**: Swift-native types with comprehensive error handling
- **Zero Dependencies**: Pure Swift implementation using Foundation

## Installation

Add swift-rfc-7617 to your package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-7617.git", from: "0.2.3")
]
```

Then add it to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 7617", package: "swift-rfc-7617")
    ]
)
```

## Quick Start

### Creating Basic Credentials

```swift
import RFC_7617

// Create Basic authentication credentials
let credentials = try RFC_7617.Basic(username: "user", password: "pass")

// Generate Authorization header value
let authHeader = credentials.authorizationHeaderValue()
// Result: "Basic dXNlcjpwYXNz"

// Get just the Base64-encoded credentials
let encoded = credentials.encoded()
// Result: "dXNlcjpwYXNz"
```

### Parsing Authorization Headers

```swift
// Parse credentials from Authorization header
let headerValue = "Basic dXNlcjpwYXNz"
let credentials = try RFC_7617.Basic.parse(from: headerValue)
// credentials.username == "user"
// credentials.password == "pass"
```

### Creating Authentication Challenges

```swift
// Create a Basic authentication challenge
let challenge = try RFC_7617.Basic.Challenge(realm: "api")

// Generate WWW-Authenticate header value
let wwwAuthHeader = challenge.wwwAuthenticateHeaderValue()
// Result: "Basic realm=\"api\""

// Create challenge with UTF-8 charset specification
let utf8Challenge = try RFC_7617.Basic.Challenge(realm: "api", charset: "UTF-8")
let utf8Header = utf8Challenge.wwwAuthenticateHeaderValue()
// Result: "Basic realm=\"api\", charset=\"UTF-8\""
```

### Parsing WWW-Authenticate Headers

```swift
// Parse challenge from WWW-Authenticate header
let headerValue = "Basic realm=\"api\", charset=\"UTF-8\""
let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
// challenge.realm == "api"
// challenge.charset == "UTF-8"
```

## Usage

### Basic Credentials Type

The `RFC_7617.Basic` type represents HTTP Basic authentication credentials:

```swift
public struct Basic: Codable, Hashable, Sendable {
    public let username: String
    public let password: String

    public init(username: String, password: String) throws
}
```

**Key Methods:**
- `encoded(charset:)` - Base64-encode credentials
- `authorizationHeaderValue()` - Generate complete Authorization header
- `parse(from:)` - Parse credentials from Authorization header

**Validation Rules:**
- Username cannot contain colon (`:`) character
- Password may contain any characters including colons
- UTF-8 encoding is fully supported

### Challenge Type

The `RFC_7617.Basic.Challenge` type represents authentication challenges:

```swift
public struct Challenge: Codable, Hashable, Sendable {
    public let realm: String
    public let charset: String?

    public init(realm: String, charset: String? = nil) throws
}
```

**Key Methods:**
- `wwwAuthenticateHeaderValue()` - Generate WWW-Authenticate header
- `parse(from:)` - Parse challenge from WWW-Authenticate header

**Validation Rules:**
- Realm parameter is required
- Charset, if specified, must be "UTF-8"

### Error Handling

The package provides comprehensive error types:

```swift
public enum Error: Swift.Error {
    case invalidUsername(String)   // Username contains colon
    case invalidFormat(String)      // Invalid header format
    case invalidEncoding(String)    // Base64 decode failed
    case invalidCharset(String)     // Unsupported charset
}
```

## Related Packages

### Used By
- Authentication middleware for Swift web frameworks
- HTTP client libraries requiring Basic authentication
- API testing tools

## Requirements

- Swift 6.0+
- macOS 13.0+ / iOS 16.0+

## License

This library is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
