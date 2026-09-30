import Testing

@testable import RFC_7617

@Suite
struct `Basic challenge quoting` {
    @Test
    func `a comma inside the quoted realm is part of the realm`() throws {
        let challenge = try RFC_7617.Basic.Challenge(#"Basic realm="api, v2", charset="UTF-8""#)
        #expect(challenge.realm == "api, v2")
        #expect(challenge.charset?.lowercased() == "utf-8")
    }

    @Test
    func `escaped quotes and backslashes in the realm are restored`() throws {
        let challenge = try RFC_7617.Basic.Challenge(#"Basic realm="say \"hi\" \\ bye""#)
        #expect(challenge.realm == #"say "hi" \ bye"#)
    }
}
