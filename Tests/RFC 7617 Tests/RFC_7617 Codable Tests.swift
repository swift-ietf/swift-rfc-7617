import Foundation
import Testing

@testable import RFC_7617

extension `RFC_7617 Tests` {
    @Suite
    struct `Codable` {

        @Test
        func `Basic encodes as its header value`() throws {
            let basic = try RFC_7617.Basic(userID: "user", password: "pa:ss")
            let data = try JSONEncoder().encode(basic)
            #expect(String(decoding: data, as: UTF8.self) == #""Basic dXNlcjpwYTpzcw==""#)
            let decoded = try JSONDecoder().decode(RFC_7617.Basic.self, from: data)
            #expect(decoded == basic)
        }

        @Test
        func `Basic decoding rejects malformed header value`() {
            let json = Data(#""Basic dXNlcg==""#.utf8)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(RFC_7617.Basic.self, from: json)
            }
        }

        @Test
        func `Basic decoding rejects keyed user-id with colon`() {
            let json = Data(#"{"userID":"user:name","password":"pass"}"#.utf8)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(RFC_7617.Basic.self, from: json)
            }
        }

        @Test
        func `Challenge round-trips through JSON`() throws {
            let challenge = try RFC_7617.Basic.Challenge(realm: "WallyWorld", charset: "UTF-8")
            let data = try JSONEncoder().encode(challenge)
            let decoded = try JSONDecoder().decode(RFC_7617.Basic.Challenge.self, from: data)
            #expect(decoded == challenge)
        }

        @Test
        func `Challenge decoding rejects non-UTF-8 charset`() {
            let json = Data(#""Basic realm=\"WallyWorld\", charset=\"ISO-8859-1\"""#.utf8)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(RFC_7617.Basic.Challenge.self, from: json)
            }
        }

        @Test
        func `Challenge decoding rejects keyed non-UTF-8 charset`() {
            let json = Data(#"{"realm":"WallyWorld","charset":"ISO-8859-1"}"#.utf8)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(RFC_7617.Basic.Challenge.self, from: json)
            }
        }
    }
}
