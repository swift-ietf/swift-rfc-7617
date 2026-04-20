// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7617 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

import Testing

@testable import RFC_7617

@Suite("RFC 7617 Tests")
struct RFC_7617_Tests {

    @Test
    func `Basic credentials creation and validation`() throws {
        let basic = try RFC_7617.Basic(userID: "user", password: "pass")
        #expect(basic.userID == "user")
        #expect(basic.password == "pass")

        // Test userID with colon throws error
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(userID: "user:name", password: "pass")
        }
    }

    @Test
    func `Basic credentials encoding via String`() throws {
        let basic = try RFC_7617.Basic(userID: "user", password: "pass")
        let headerValue = String(basic)
        #expect(headerValue == "Basic dXNlcjpwYXNz")
    }

    @Test
    func `Basic credentials encoding via [UInt8]`() throws {
        let basic = try RFC_7617.Basic(userID: "user", password: "pass")
        let bytes = [UInt8](basic)
        let expected = Array("Basic dXNlcjpwYXNz".utf8)
        #expect(bytes == expected)
    }

    @Test
    func `Basic credentials parsing from Authorization header`() throws {
        let headerValue = "Basic dXNlcjpwYXNz"  // "user:pass"
        let basic = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(basic.userID == "user")
        #expect(basic.password == "pass")
    }

    @Test
    func `Basic credentials parsing case-insensitive prefix`() throws {
        let headerValue = "basic dXNlcjpwYXNz"  // lowercase "basic"
        let basic = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(basic.userID == "user")
        #expect(basic.password == "pass")
    }

    @Test
    func `Basic credentials parsing error cases`() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(ascii: "Bearer dXNlcjpwYXNz".utf8)
        }

        // Invalid Base64
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(ascii: "Basic !!!invalid".utf8)
        }

        // Missing colon separator
        let noColonBase64 = "dXNlcnBhc3M="  // Base64 of "userpass"
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(ascii: "Basic \(noColonBase64)".utf8)
        }

        // Empty input
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(ascii: "".utf8)
        }
    }

    @Test
    func `Basic credentials with UTF-8 characters`() throws {
        let basic = try RFC_7617.Basic(userID: "user", password: "páss")
        let headerValue = String(basic)
        let decoded = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(decoded.userID == "user")
        #expect(decoded.password == "páss")
    }

    @Test
    func `Basic.Challenge creation and validation`() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)

        let challengeWithCharset = try RFC_7617.Basic.Challenge(
            realm: "test-realm",
            charset: "UTF-8"
        )
        #expect(challengeWithCharset.charset == "UTF-8")

        // Test invalid charset
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(realm: "test-realm", charset: "ISO-8859-1")
        }
    }

    @Test
    func `Basic.Challenge WWW-Authenticate header generation`() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        let headerValue = String(challenge)
        #expect(headerValue == #"Basic realm="test-realm""#)

        let challengeWithCharset = try RFC_7617.Basic.Challenge(
            realm: "test-realm",
            charset: "UTF-8"
        )
        let headerValueWithCharset = String(challengeWithCharset)
        #expect(headerValueWithCharset == #"Basic realm="test-realm", charset="UTF-8""#)
    }

    @Test
    func `Basic.Challenge parsing from WWW-Authenticate header`() throws {
        let headerValue = "Basic realm=\"test-realm\""
        let challenge = try RFC_7617.Basic.Challenge(ascii: headerValue.utf8)
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)

        let headerValueWithCharset = #"Basic realm=test-realm, charset=UTF-8"#
        let challengeWithCharset = try RFC_7617.Basic.Challenge(ascii: headerValueWithCharset.utf8)
        #expect(challengeWithCharset.realm == "test-realm")
        #expect(challengeWithCharset.charset == "UTF-8")
    }

    @Test
    func `Basic.Challenge parsing error cases`() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(ascii: "Digest realm=\"test\"".utf8)
        }

        // Missing realm parameter
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(ascii: "Basic charset=\"UTF-8\"".utf8)
        }

        // Empty input
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(ascii: "".utf8)
        }
    }

    @Test
    func `Basic.Challenge parsing with unquoted values`() throws {
        let headerValue = "Basic realm=test-realm"
        let challenge = try RFC_7617.Basic.Challenge(ascii: headerValue.utf8)
        #expect(challenge.realm == "test-realm")
    }

    @Test
    func `RFC 7617.Basic.Error descriptions`() {
        let userIDError = RFC_7617.Basic.Error.invalidUserID("test:user", reason: "contains colon")
        #expect(userIDError.description.contains("test:user"))

        let formatError = RFC_7617.Basic.Error.invalidFormat("invalid", reason: "bad format")
        #expect(formatError.description.contains("invalid"))

        let encodingError = RFC_7617.Basic.Error.invalidEncoding("data", reason: "bad encoding")
        #expect(encodingError.description.contains("data"))

        let charsetError = RFC_7617.Basic.Error.invalidCharset("ISO-8859-1")
        #expect(charsetError.description.contains("ISO-8859-1"))

        let emptyError = RFC_7617.Basic.Error.empty
        #expect(emptyError.description.contains("empty"))
    }

    @Test
    func `Edge case: empty userID or password`() throws {
        let basicEmptyUserID = try RFC_7617.Basic(userID: "", password: "pass")
        #expect(basicEmptyUserID.userID.isEmpty)
        #expect(basicEmptyUserID.password == "pass")

        let basicEmptyPassword = try RFC_7617.Basic(userID: "user", password: "")
        #expect(basicEmptyPassword.userID == "user")
        #expect(basicEmptyPassword.password.isEmpty)

        // Test round-trip encoding/decoding
        let headerValue = String(basicEmptyUserID)
        let decoded = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(decoded.userID.isEmpty)
        #expect(decoded.password == "pass")
    }

    @Test
    func `Edge case: password with colon`() throws {
        let basic = try RFC_7617.Basic(userID: "user", password: "pass:word")
        #expect(basic.userID == "user")
        #expect(basic.password == "pass:word")

        // Test round-trip encoding/decoding
        let headerValue = String(basic)
        let decoded = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(decoded.userID == "user")
        #expect(decoded.password == "pass:word")
    }

    @Test
    func `Hashable conformance`() throws {
        let basic1 = try RFC_7617.Basic(userID: "user", password: "pass")
        let basic2 = try RFC_7617.Basic(userID: "user", password: "pass")
        let basic3 = try RFC_7617.Basic(userID: "user", password: "different")

        #expect(basic1 == basic2)
        #expect(basic1.hashValue == basic2.hashValue)
        #expect(basic1 != basic3)
    }

    @Test
    func `Challenge Hashable conformance`() throws {
        let challenge1 = try RFC_7617.Basic.Challenge(realm: "test")
        let challenge2 = try RFC_7617.Basic.Challenge(realm: "test")
        let challenge3 = try RFC_7617.Basic.Challenge(realm: "other")

        #expect(challenge1 == challenge2)
        #expect(challenge1.hashValue == challenge2.hashValue)
        #expect(challenge1 != challenge3)
    }

    @Test
    func `RFC 7617 example: Aladdin`() throws {
        // Per RFC 7617 Section 2: "Aladdin:open sesame" -> "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        let basic = try RFC_7617.Basic(userID: "Aladdin", password: "open sesame")
        let headerValue = String(basic)
        #expect(headerValue == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")

        // Round-trip
        let parsed = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(parsed.userID == "Aladdin")
        #expect(parsed.password == "open sesame")
    }
}
