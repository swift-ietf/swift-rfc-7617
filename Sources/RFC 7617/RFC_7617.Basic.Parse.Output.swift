extension RFC_7617.Basic.Parse {
    public struct Output: Sendable {
        /// The raw Base64-encoded credentials (everything after "Basic ")
        public let token68: Input

        @inlinable
        public init(token68: Input) {
            self.token68 = token68
        }
    }
}
