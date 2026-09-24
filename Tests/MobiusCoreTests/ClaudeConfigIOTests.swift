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

    /// 안정 읽기는 두 읽기 사이에 **조직이 바뀌면**(같은 이메일·같은 토큰이라도) 불안정으로 본다 —
    /// 같은 이메일의 다른 워크스페이스로 로그인이 끝나는 찰나에 옛 토큰과 새 조직이 짝지어지는 것을 막는다.
    func testStableReadRejectsOrganizationChangeBetweenReads() async throws {
        try seedLive()
        func claudeJSON(org: String) -> Data {
            Data(#"{"oauthAccount":{"emailAddress":"p@x.com","organizationName":"O","organizationUuid":"\#(org)"}}"#.utf8)
        }
        try claudeJSON(org: "org-A").write(to: env.claudeJSON)
        let stable = await io.readStableLiveSnapshot(gap: .milliseconds(50))
        XCTAssertNotNil(stable, "변화가 없으면 안정")

        let url = env.claudeJSON
        let flip = Task.detached {
            try? await Task.sleep(for: .milliseconds(120))
            try? claudeJSON(org: "org-B").write(to: url)
        }
        let unstable = await io.readStableLiveSnapshot(gap: .milliseconds(400))
        await flip.value
        XCTAssertNil(unstable, "토큰·이메일이 같아도 조직이 바뀌면 불안정으로 봐야 한다")
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

        // Team 워크스페이스 실측: organizationType·organizationRateLimitTier가 null, seatTier만 온다
        let teamSeat = #"{"oauthAccount":{"emailAddress":"p@x.com","organizationName":"acme-team","organizationType":null,"organizationRateLimitTier":null,"seatTier":"team_tier_1","organizationUuid":"5d1f0c9e-0000-0000-0000-000000000000"}}"#
        try Data(teamSeat.utf8).write(to: env.claudeJSON)
        XCTAssertEqual(try XCTUnwrap(io.liveIdentity()).tierDescription, "Team Tier 1",
                       "등급 필드가 전부 null이면 seatTier로 폴백해야 부제가 비지 않는다")
        try Data(withOrg.utf8).write(to: env.claudeJSON)

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

    // MARK: 라이브 스냅샷 저장 판정 (실패 기록 24)
    // 실측 2026-09-24의 두 oauthAccount 모양 — 같은 이메일·같은 accountUuid, 조직만 다르다.

    static let teamAccount = #"{"emailAddress":"p@x.com","organizationName":"acme-team","organizationType":"claude_team","organizationRateLimitTier":"default_raven","userRateLimitTier":"default_claude_max_5x","seatTier":"team_tier_1","organizationUuid":"org-team"}"#
    static let maxAccount = #"{"emailAddress":"p@x.com","organizationName":"p@x.com's Organization","organizationType":"claude_max","organizationRateLimitTier":"default_claude_max_20x","userRateLimitTier":null,"seatTier":null,"organizationUuid":"org-max"}"#

    func liveSnap(subscription: String?, refresh: String? = "R", account: String) -> CredentialsSnapshot {
        var oauth: [String: Any] = ["accessToken": "A", "expiresAt": 1]
        if let refresh { oauth["refreshToken"] = refresh }
        if let subscription { oauth["subscriptionType"] = subscription }
        let blob = try! JSONSerialization.data(withJSONObject: ["claudeAiOauth": oauth, "mcpOAuth": [:]])
        return CredentialsSnapshot(keychainBlob: blob, credentialsFileData: blob,
                                   oauthAccountJSON: Data(account.utf8))
    }

    func testVerdictAcceptsMatchingTokenAndAccount() {
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "team", account: Self.teamAccount)), .storable)
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "max", account: Self.maxAccount)), .storable)
    }

    /// 사고의 모양 그대로: 개인 Max 프로필 자리(oauthAccount = Max)에 Team 토큰이 들어온 라이브.
    /// 이걸 저장하면 두 카드가 같은 사용량을 보이고, 한쪽이 회전할 때마다 다른 쪽이 invalid_grant가 된다.
    func testVerdictRejectsTokenFromOtherOrganizationKind() {
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "team", account: Self.maxAccount)),
                       .organizationMismatch)
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "max", account: Self.teamAccount)),
                       .organizationMismatch)
    }

    /// seatTier가 organizationType보다 먼저다 — 로그인 때 organizationUuid와 함께 쓰이는 쪽이 seatTier다.
    func testVerdictPrefersSeatTierOverOrganizationType() {
        let staleType = #"{"emailAddress":"p@x.com","organizationType":"claude_max","seatTier":"team_tier_1","organizationUuid":"org-team"}"#
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "team", account: staleType)), .storable)
    }

    /// 개인 구독 안에서 요금제가 바뀌어도(Pro→Max) 막지 않는다 — claude는 refresh 때 blob의
    /// subscriptionType을 이전 값 그대로 물려주므로 둘이 한동안 달라진다.
    func testVerdictIgnoresPlanChangeWithinPersonalSubscription() {
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "pro", account: Self.maxAccount)), .storable)
    }

    /// 로그아웃·재로그인 도중의 모양 둘 — 토큰만 비운 blob, 로그인 항목을 통째로 지운 blob.
    func testVerdictRejectsLoggedOutBlobs() {
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "team", refresh: "", account: Self.teamAccount)),
                       .loggedOut)
        let onlyMcp = Data(#"{"mcpOAuth":{"srv|1":{"accessToken":"m","refreshToken":"mr"}}}"#.utf8)
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(CredentialsSnapshot(keychainBlob: onlyMcp, credentialsFileData: onlyMcp,
                                                                              oauthAccountJSON: Data(Self.teamAccount.utf8))),
                       .loggedOut)
        // MCP 항목이 없는 사용자에게는 재로그인 준비 단계가 빈 객체를 남긴다(리뷰 P2)
        let empty = Data("{}".utf8)
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(CredentialsSnapshot(keychainBlob: empty, credentialsFileData: empty,
                                                                              oauthAccountJSON: Data(Self.teamAccount.utf8))),
                       .loggedOut)
    }

    /// 판정 근거가 없으면 막지 않는다 — 구버전 claude(subscriptionType·seatTier 없음)와 테스트 blob.
    func testVerdictIsPermissiveWhenSignalsAreMissing() {
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: nil, account: Self.maxAccount)), .storable)
        let bare = #"{"emailAddress":"p@x.com","organizationUuid":"org-x"}"#
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(liveSnap(subscription: "team", account: bare)), .storable)
        let opaque = Data(#"{"tok":"x"}"#.utf8)
        XCTAssertEqual(ClaudeConfigIO.liveSnapshotVerdict(CredentialsSnapshot(keychainBlob: opaque, credentialsFileData: opaque,
                                                                              oauthAccountJSON: Data(Self.maxAccount.utf8))),
                       .storable)
    }

    /// Team의 organizationRateLimitTier는 내부 코드명("default_raven")으로 온다(실측) — 등급 칸엔 "Team".
    func testTierDescriptionShowsTeamInsteadOfRateLimitCodename() throws {
        func tier(_ json: String) throws -> String {
            let block = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
            return ClaudeConfigIO.tierDescription(from: block)
        }
        XCTAssertEqual(try tier(Self.teamAccount), "Team")
        XCTAssertEqual(try tier(Self.maxAccount), "Max 20x")
        XCTAssertEqual(try tier(#"{"organizationType":"claude_enterprise","organizationRateLimitTier":"default_x"}"#), "Enterprise")
    }
}
