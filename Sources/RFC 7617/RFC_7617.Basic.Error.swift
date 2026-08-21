extension RFC_7617.Basic {

    public enum Error: Swift.Error, Sendable, Equatable {

        case empty

        case invalidUserID(_ value: String, reason: String)

        case invalidFormat(_ value: String, reason: String)

        case invalidEncoding(_ value: String, reason: String)

        case invalidCharset(_ value: String)
    }
}

extension RFC_7617.Basic.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .empty:
            return "Input cannot be empty"

        case .invalidUserID(let value, let reason):
            return "Invalid user-id '\(value)': \(reason)"

        case .invalidFormat(let value, let reason):
            return "Invalid format '\(value)': \(reason)"

        case .invalidEncoding(let value, let reason):
            return "Invalid encoding '\(value)': \(reason)"

        case .invalidCharset(let value):
            return "Invalid charset '\(value)': only UTF-8 is supported"
        }
    }
}
