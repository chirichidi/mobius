import XCTest
@testable import MobiusCore

final class ClaudeConfigIOTests: XCTestCase {
    var tmp: URL!
    var env: MobiusEnvironment!
    var kc: InMemoryKeychain!
    var io: ClaudeConfigIO!

    override func setUpWithError() throws {
        tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("mobius-test-\(UUID().uuidString)")
        env = MobiusEnvironment(home: tmp, localUser: "tester")
        try FileManager.default.createDirectory(at: env.claudeDir,
                                                withIntermediateDirectories: true)
        kc = InMemoryKeychain()
        io = ClaudeConfigIO(env: env, keychain: kc)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: tmp) }

    func seedLive(email: String = "p@x.com") throws {
        try kc.write(service: env.claudeKeychainService, account: env.claudeKeychainAccount,
                     data: Data(#"{"tok":"secret-A"}"#.utf8))
        try Data(#"{"tok":"secret-A"}"#.utf8).write(to: env.credentialsFile)
        let claudeJSON = #"{"otherKey":42,"oauthAccount":{"emailAddress":"\#(email)","organizationName":"Org"}}"#
        try Data(claudeJSON.utf8).write(to: env.claudeJSON)
    }

    func testReadLiveSnapshot() throws {
        try seedLive()
        let snap = try XCTUnwrap(io.readLiveSnapshot())
        XCTAssertEqual(snap.keychainBlob, Data(#"{"tok":"secret-A"}"#.utf8))
        XCTAssertEqual(snap.credentialsFileData, Data(#"{"tok":"secret-A"}"#.utf8))
        XCTAssertEqual(try io.liveEmail(), "p@x.com")
    }

    func testReadReturnsNilWithoutKeychain() throws {
        XCTAssertNil(try io.readLiveSnapshot())
    }

    /// 계정 열쇠 = 이메일 + organizationUuid. 조직 필드가 없는 옛 claude.json은 ""(조직 미상).
    func testLiveAccountKeyCarriesOrganizationUuid() throws {
        try seedLive()
        XCTAssertEqual(try io.liveAccountKey(), AccountKey(emailAddress: "p@x.com"))

        let withOrg = #"{"oauthAccount":{"emailAddress":"p@x.com","organizationName":"acme-team","organizationType":"claude_team","organizationUuid":"5d1f0c9e-0000-0000-0000-000000000000"}}"#
        try Data(withOrg.utf8).write(to: env.claudeJSON)
        XCTAssertEqual(try io.liveAccountKey(),
                       AccountKey(emailAddress: "p@x.com", organizationUuid: "5d1f0c9e-0000-0000-0000-000000000000"))
        let identity = try XCTUnwrap(io.liveIdentity())
        XCTAssertEqual(identity.organizationUuid, "5d1f0c9e-0000-0000-0000-000000000000")
        XCTAssertEqual(identity.organizationName, "acme-team")
        XCTAssertEqual(identity.tierDescription, "Team")

        // 스냅샷에서도 같은 신원이 나온다(구버전 프로필 조직 채우기·CLI capture가 쓰는 경로)
        let snap = try XCTUnwrap(io.readLiveSnapshot())
        XCTAssertEqual(ClaudeConfigIO.identity(fromSnapshot: snap)?.key, identity.key)
    }

    func testWritePreservesOtherKeys() throws {
        try seedLive()
        var snap = try XCTUnwrap(io.readLiveSnapshot())
        snap.keychainBlob = Data(#"{"tok":"secret-B"}"#.utf8)
        snap.credentialsFileData = Data(#"{"tok":"secret-B"}"#.utf8)
        snap.oauthAccountJSON = Data(#"{"emailAddress":"w@x.com"}"#.utf8)
        try io.writeLiveSnapshot(snap)

        XCTAssertEqual(try kc.read(service: env.claudeKeychainService,
                                   account: env.claudeKeychainAccount),
                       Data(#"{"tok":"secret-B"}"#.utf8))
        XCTAssertEqual(try Data(contentsOf: env.credentialsFile),
                       Data(#"{"tok":"secret-B"}"#.utf8))
        let dict = try JSONSerialization.jsonObject(
            with: Data(contentsOf: env.claudeJSON)) as! [String: Any]
        XCTAssertEqual(dict["otherKey"] as? Int, 42) // 다른 키 보존
        XCTAssertEqual((dict["oauthAccount"] as? [String: Any])?["emailAddress"] as? String,
                       "w@x.com")
        XCTAssertEqual(try io.liveEmail(), "w@x.com")
    }
}
