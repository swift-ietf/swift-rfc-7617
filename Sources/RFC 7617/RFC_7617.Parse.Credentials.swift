//
//  RFC_7617.Parse.Credentials.swift
//  swift-rfc-7617
//
//  HTTP Basic Authentication: "Basic" SP base64(user:pass)
//

public import Parser_Primitives

extension RFC_7617.Parse {
    /// Parses HTTP Basic Authentication credentials per RFC 7617 Section 2.
    ///
    /// `credentials = "Basic" 1*SP token68`
    ///
    /// Where `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
    ///
    /// Returns the raw Base64-encoded token (decoding is left to the caller).
    /// The prefix match is case-insensitive.
    public struct Credentials<Input: Collection.Slice.`Protocol`>: Sendable
    where Input: Sendable, Input.Element == UInt8 {
        @inlinable
        public init() {}
    }
}

extension RFC_7617.Parse.Credentials {
    public struct Output: Sendable {
        /// The raw Base64-encoded credentials (everything after "Basic ")
        public let token68: Input

        @inlinable
        public init(token68: Input) {
            self.token68 = token68
        }
    }

    public enum Error: Swift.Error, Sendable, Equatable {
        case expectedBasicPrefix
        case expectedSpace
        case emptyToken
    }
}

extension RFC_7617.Parse.Credentials: Parser.`Protocol` {
    public typealias ParseOutput = Output
    public typealias Failure = RFC_7617.Parse.Credentials<Input>.Error

    @inlinable
    public func parse(_ input: inout Input) throws(Failure) -> Output {
        // Case-insensitive match for "Basic" (5 bytes)
        var idx = input.startIndex
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        // B/b
        guard input[idx] == 0x42 || input[idx] == 0x62 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        // a
        guard input[idx] == 0x61 || input[idx] == 0x41 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        // s
        guard input[idx] == 0x73 || input[idx] == 0x53 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        // i
        guard input[idx] == 0x69 || input[idx] == 0x49 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        // c
        guard input[idx] == 0x63 || input[idx] == 0x43 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)

        // Expect at least one SP (0x20)
        guard idx < input.endIndex, input[idx] == 0x20 else { throw .expectedSpace }
        // Skip all spaces
        while idx < input.endIndex && input[idx] == 0x20 {
            input.formIndex(after: &idx)
        }

        // Consume token68 chars
        let tokenStart = idx
        while idx < input.endIndex {
            let byte = input[idx]
            guard Self._isToken68Char(byte) else { break }
            input.formIndex(after: &idx)
        }
        // Consume trailing '=' padding
        while idx < input.endIndex && input[idx] == 0x3D {
            input.formIndex(after: &idx)
        }

        guard idx > tokenStart else { throw .emptyToken }

        let token68 = input[tokenStart..<idx]
        input = input[idx...]
        return Output(token68: token68)
    }

    @inlinable
    static func _isToken68Char(_ byte: UInt8) -> Bool {
        return switch byte {
        case 0x41...0x5A: true  // A-Z
        case 0x61...0x7A: true  // a-z
        case 0x30...0x39: true  // 0-9
        case 0x2D: true         // -
        case 0x2E: true         // .
        case 0x5F: true         // _
        case 0x7E: true         // ~
        case 0x2B: true         // +
        case 0x2F: true         // /
        default: false
        }
    }
}
