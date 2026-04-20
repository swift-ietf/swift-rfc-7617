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

import RFC_7617
import Testing

@Suite("README Verification")
struct ReadmeVerificationTests {

    @Test
    func `Create Basic authentication credentials`() throws {
        let credentials = try RFC_7617.Basic(userID: "user", password: "pass")

        // Serialize to Authorization header
        let authHeader = String(credentials)
        #expect(authHeader == "Basic dXNlcjpwYXNz")
    }

    @Test
    func `Parse credentials from Authorization header`() throws {
        let headerValue = "Basic dXNlcjpwYXNz"
        let credentials = try RFC_7617.Basic(ascii: headerValue.utf8)
        #expect(credentials.userID == "user")
        #expect(credentials.password == "pass")
    }

    @Test
    func `Create authentication challenges`() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "api")

        let wwwAuthHeader = String(challenge)
        #expect(wwwAuthHeader == #"Basic realm="api""#)

        let utf8Challenge = try RFC_7617.Basic.Challenge(realm: "api", charset: "UTF-8")
        let utf8Header = String(utf8Challenge)
        #expect(utf8Header == #"Basic realm="api", charset="UTF-8""#)
    }

    @Test
    func `Parse challenge from WWW-Authenticate header`() throws {
        let headerValue = "Basic realm=\"api\", charset=\"UTF-8\""
        let challenge = try RFC_7617.Basic.Challenge(ascii: headerValue.utf8)
        #expect(challenge.realm == "api")
        #expect(challenge.charset == "UTF-8")
    }
}
