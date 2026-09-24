import XCTest
@testable import MobiusCore

private final class MockRefresher: TokenRefresher, @unchecked Sendable {
    var result: Result<RefreshedTokens, Error>
    private(set) var callCount = 0
    private(set) var lastRefreshToken: String?
    init(_ r: Result<RefreshedTokens, Error>) { result = r }
    func refresh(refreshToken: String, scopes: [String], now: Date) async throws -> RefreshedTokens {
        callCount += 1
        lastRefreshToken = refreshToken
        return try result.get()
    }
}

/// release()가 불릴 때까지 refresh 응답을 붙잡아 두는 mock — 동시 합류 테스트용.
/// release 이후의 호출은 즉시 반환한다(테스트가 행 걸리지 않게).
private final class GatedRefresher: TokenRefresher, @unchecked Sendable {
    let tokens: RefreshedTokens
    private(set) var callCount = 0
    var onEnter: (@Sendable () -> Void)?
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var released = false
    private let lock = NSLock()
    init(tokens: RefreshedTokens) { self.tokens = tokens }

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    func refresh(refreshToken: String, scopes: [String], now: Date) async throws -> RefreshedTokens {
        let (enter, done): ((@Sendable () -> Void)?, Bool) = withLock {
            callCount += 1
            return (onEnter, released)
        }
        enter?()
        if !done {
            await withCheckedContinuation { c in
                withLock {
                    if released { c.resume() } else { waiters.append(c) }
                }
            }
        }
        return tokens
    }

    func release() {
        let ws: [CheckedContinuation<Void, Never>] = withLock {
            released = true
            let w = waiters; waiters = []
            return w
        }
        ws.forEach { $0.resume() }
    }
}

final class FallbackAuthCheckerTests: XCTestCase {
    var tmp: URL!; var env: MobiusEnvironment!; var kc: InMemoryKeychain!; var store: AccountStore!
    var active: AccountProfile!; var fallback: AccountProfile!
    // rte 미래(살아있음) / 과거(로컬 만료) 판정 기준시각
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    let futureRteMs = 1_900_000_000_000     // ≈2030 (now 이후)
    let pastRteMs = 1_500_000_000_000        // ≈2017 ms (now 이전, ms 판별 임계 1e12 초과)

    func snap(email: String, rt: String, rteMs: Int, hasRefresh: Bool = true) -> CredentialsSnapshot {
        let oauth = hasRefresh
            ? #"{"accessToken":"AT","refreshToken":"\#(rt)","expiresAt":1,"refreshTokenExpiresAt":\#(rteMs),"scopes":["user:inference","user:profile"],"subscriptionType":"max"}"#
            : #"{"accessToken":"AT"}"#
        let blob = Data(#"{"claudeAiOauth":\#(oauth)}"#.utf8)
        return CredentialsSnapshot(keychainBlob: blob, credentialsFileData: blob,
            oauthAccountJSON: Data(#"{"emailAddress":"\#(email)","organizationName":"O"}"#.utf8))
    }

    override func setUpWithError() throws {
        tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("mobius-fac-\(UUID().uuidString)")
        env = MobiusEnvironment(home: tmp, localUser: "tester")
        try FileManager.default.createDirectory(at: env.claudeDir, withIntermediateDirectories: true)
        kc = InMemoryKeychain()
        store = try AccountStore(env: env, keychain: kc)
        active = try store.upsertProfile(nickname: "active", snapshot: snap(email: "a@x.com", rt: "ART", rteMs: futureRteMs))
        fallback = try store.upsertProfile(nickname: "fallback", snapshot: snap(email: "f@x.com", rt: "FRT", rteMs: futureRteMs))
        try store.setActive(active.id)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: tmp) }

    private func reauth(_ id: UUID) -> Bool {
        store.file.accounts.first { $0.id == id }?.needsReauth ?? false
    }

    func testRefreshSuccessStoresNewTokenAndClearsReauth() async throws {
        try store.setNeedsReauth(fallback.id, true) // 잘못 남은 딱지가 해제되는지도 확인
        let tokens = RefreshedTokens(accessToken: "NAT", refreshToken: "NRT",
                                     expiresAtMs: 123, refreshTokenExpiresAtMs: futureRteMs + 1, scopes: nil)
        let mock = MockRefresher(.success(tokens))
        let checker = FallbackAuthChecker(store: store, refresher: mock)
        let r = await checker.check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .refreshedAlive)
        XCTAssertEqual(mock.callCount, 1)
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: fallback.id)).keychainBlob), "NRT")
        XCTAssertFalse(reauth(fallback.id)) // 살아있음 → 해제
    }

    func testInvalidGrantMarksReauth() async throws {
        let mock = MockRefresher(.failure(TokenRefresherError.invalidGrant))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .dead)
        XCTAssertTrue(reauth(fallback.id))
    }

    func testLocallyDeadSkipsNetwork() async throws {
        // refreshTokenExpiresAt 과거 → 네트워크 호출 없이 죽음 판정
        try store.setSecret(snap(email: "f@x.com", rt: "FRT", rteMs: pastRteMs), for: fallback.id)
        let mock = MockRefresher(.failure(TokenRefresherError.invalidGrant))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .locallyDead)
        XCTAssertEqual(mock.callCount, 0)         // 네트워크 0
        XCTAssertTrue(reauth(fallback.id))
    }

    func testActiveAccountNeverRefreshed() async throws {
        let mock = MockRefresher(.failure(TokenRefresherError.invalidGrant))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(active.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .notFallback)
        XCTAssertEqual(mock.callCount, 0)
        XCTAssertFalse(reauth(active.id))         // 활성은 절대 마킹 안 함
    }

    func testTransientDoesNotMarkReauth() async throws {
        let mock = MockRefresher(.failure(TokenRefresherError.transient))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .transient)
        XCTAssertFalse(reauth(fallback.id))       // 일시적 오류로 죽음 단정 금지
    }

    func testMissingRefreshTokenMarksReauth() async throws {
        try store.setSecret(snap(email: "f@x.com", rt: "-", rteMs: futureRteMs, hasRefresh: false), for: fallback.id)
        let mock = MockRefresher(.failure(TokenRefresherError.transient))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .noRefreshToken)
        XCTAssertEqual(mock.callCount, 0)
        XCTAssertTrue(reauth(fallback.id))
    }

    // 같은 계정 동시 check는 refresh를 한 번만 쏘고 결과에 합류한다 — 동시 이중 refresh가
    // 회전된 토큰으로 invalid_grant를 받아 살아있는 계정을 오마킹하는 레이스 방지.
    func testConcurrentChecksCoalesceToSingleRefresh() async throws {
        let tokens = RefreshedTokens(accessToken: "NAT", refreshToken: "NRT",
                                     expiresAtMs: 123, refreshTokenExpiresAtMs: futureRteMs + 1, scopes: nil)
        let gated = GatedRefresher(tokens: tokens)
        let checker = FallbackAuthChecker(store: store, refresher: gated)
        let id = fallback.id, activeID = active.id, ts = now

        // 첫 호출이 refresh 안에서 붙잡혀 있는 동안 —
        let entered = expectation(description: "refresh entered")
        gated.onEnter = { entered.fulfill() }
        let t1 = Task { await checker.check(id, activeAccountID: activeID, now: ts) }
        await fulfillment(of: [entered], timeout: 2)

        // — 두 번째 호출은 새 refresh 없이 합류해야 한다. 합류 관측 후에만 release (결정적).
        let t2 = Task { await checker.check(id, activeAccountID: activeID, now: ts) }
        let deadline = Date().addingTimeInterval(2)
        while checker.coalescedJoins == 0 && Date() < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(checker.coalescedJoins, 1)
        gated.release()

        let r1 = await t1.value, r2 = await t2.value
        XCTAssertEqual(r1, .refreshedAlive)
        XCTAssertEqual(r2, .refreshedAlive)
        XCTAssertEqual(gated.callCount, 1)   // ★ refresh는 단 1회
        XCTAssertEqual(CredentialBlob.refreshToken(
            from: try XCTUnwrap(store.secret(for: fallback.id)).keychainBlob), "NRT")
        XCTAssertFalse(reauth(fallback.id))
    }

    // 완료 후에는 게이트가 풀린다 — 순차 check는 각자 refresh하고, 두 번째는
    // 첫 회전이 저장한 새 refresh 토큰을 다시 읽어 보낸다 (낡은 토큰 전송 금지).
    func testSequentialChecksReuseRotatedToken() async throws {
        let tokens = RefreshedTokens(accessToken: "NAT", refreshToken: "NRT",
                                     expiresAtMs: 123, refreshTokenExpiresAtMs: futureRteMs + 1, scopes: nil)
        let mock = MockRefresher(.success(tokens))
        let checker = FallbackAuthChecker(store: store, refresher: mock)
        let r1 = await checker.check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r1, .refreshedAlive)
        XCTAssertEqual(mock.lastRefreshToken, "FRT")   // 최초 저장분
        let r2 = await checker.check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r2, .refreshedAlive)
        XCTAssertEqual(mock.callCount, 2)              // 게이트 해제 — 완료 후엔 각자 refresh
        XCTAssertEqual(mock.lastRefreshToken, "NRT")   // ★ 회전된 토큰을 다시 읽어서 사용
    }

    // MARK: 조직 대조와 저장 직전 재확인 (실패 기록 24)

    private func orgFallback(org: String) throws -> AccountProfile {
        let oauth = #"{"accessToken":"AT","refreshToken":"ORT","expiresAt":1,"refreshTokenExpiresAt":\#(futureRteMs),"scopes":["user:inference"],"subscriptionType":"team"}"#
        let blob = Data(#"{"claudeAiOauth":\#(oauth)}"#.utf8)
        return try store.upsertProfile(nickname: "team", snapshot: CredentialsSnapshot(
            keychainBlob: blob, credentialsFileData: blob,
            oauthAccountJSON: Data(#"{"emailAddress":"t@x.com","organizationName":"acme","organizationUuid":"\#(org)"}"#.utf8)))
    }

    private func tokens(org: String?) -> RefreshedTokens {
        RefreshedTokens(accessToken: "NAT", refreshToken: "NRT", expiresAtMs: 123,
                        refreshTokenExpiresAtMs: futureRteMs + 1, scopes: nil, organizationUuid: org)
    }

    /// refresh 응답이 다른 조직의 토큰이라고 말하면 — 저장 스냅샷이 남의 조직 토큰을 들고 있었다.
    /// 회전본을 이 프로필에 넣지 않고 재로그인 필요로 마킹한다. 같은 종류의 두 조직(Team과 다른
    /// Team)도 여기서 갈린다(라이브 판정은 좌석형/개인 구독만 본다).
    func testRefreshFromAnotherOrganizationIsNotStored() async throws {
        let team = try orgFallback(org: "org-team")
        let r = await FallbackAuthChecker(store: store, refresher: MockRefresher(.success(tokens(org: "org-other"))))
            .check(team.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .organizationMismatch)
        XCTAssertTrue(reauth(team.id))
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: team.id)).keychainBlob), "ORT")
    }

    func testRefreshFromSameOrganizationOrUnknownIsStored() async throws {
        let team = try orgFallback(org: "org-team")
        let same = await FallbackAuthChecker(store: store, refresher: MockRefresher(.success(tokens(org: "org-team"))))
            .check(team.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(same, .refreshedAlive)
        // 응답에 조직이 없으면(구버전 서버 응답) 예전처럼 저장한다 — 모르면 막지 않는다.
        let unknown = await FallbackAuthChecker(store: store, refresher: MockRefresher(.success(tokens(org: nil))))
            .check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(unknown, .refreshedAlive)
    }

    /// HTTP 왕복 사이에 재로그인이 이 프로필에 새 스냅샷을 썼으면, 옛 계보의 회전본으로 덮지 않는다.
    func testRotationDoesNotOverwriteSnapshotSavedDuringRefresh() async throws {
        let gated = GatedRefresher(tokens: tokens(org: nil))
        let checker = FallbackAuthChecker(store: store, refresher: gated)
        let id = fallback.id, activeID = active.id, ts = now
        let entered = expectation(description: "refresh entered")
        gated.onEnter = { entered.fulfill() }
        let task = Task { await checker.check(id, activeAccountID: activeID, now: ts) }
        await fulfillment(of: [entered], timeout: 2)

        try store.setSecret(snap(email: "f@x.com", rt: "RELOGIN", rteMs: futureRteMs), for: fallback.id)
        gated.release()

        let r = await task.value
        XCTAssertEqual(r, .transient)
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: fallback.id)).keychainBlob), "RELOGIN")
    }

    /// 사고 뒤 업그레이드한 사용자의 모양: 개인 Max 카드의 저장본에 Team 토큰이 들어 있다. 이걸 refresh하면
    /// 같은 토큰을 쥔 라이브·Team 카드까지 죽는다 — 네트워크 없이 먼저 잡아야 한다(리뷰 P1).
    func testMixedStoredSnapshotIsFlaggedWithoutRefresh() async throws {
        let blob = Data(#"{"claudeAiOauth":{"accessToken":"AT","refreshToken":"SHARED","expiresAt":1,"refreshTokenExpiresAt":\#(futureRteMs),"subscriptionType":"team"}}"#.utf8)
        let mixed = try store.upsertProfile(nickname: "max", snapshot: CredentialsSnapshot(
            keychainBlob: blob, credentialsFileData: blob,
            oauthAccountJSON: Data(#"{"emailAddress":"t@x.com","organizationType":"claude_max","seatTier":null,"organizationUuid":"org-max"}"#.utf8)))
        let mock = MockRefresher(.success(tokens(org: "org-team")))
        let checker = FallbackAuthChecker(store: store, refresher: mock)

        let local = await checker.check(mixed.id, activeAccountID: active.id, now: now, allowNetwork: false)
        XCTAssertEqual(local, .mixedSnapshot, "팝오버의 로컬 검증에서도 잡힌다")
        try store.setNeedsReauth(mixed.id, false)
        let network = await checker.check(mixed.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(network, .mixedSnapshot)
        XCTAssertEqual(mock.callCount, 0, "공유 계보를 소비하면 안 된다")
        XCTAssertTrue(reauth(mixed.id))
    }

    /// 두 프로필이 같은 refresh 토큰을 쥐고 있으면 refresh하지 않는다 — 조직 종류가 같거나
    /// subscriptionType이 없어 스냅샷 판정이 못 가르는 경우의 안전장치.
    func testSharedRefreshTokenIsNotRefreshed() async throws {
        try store.setSecret(snap(email: "a@x.com", rt: "FRT", rteMs: futureRteMs), for: active.id)
        let mock = MockRefresher(.success(tokens(org: nil)))
        let r = await FallbackAuthChecker(store: store, refresher: mock).check(fallback.id, activeAccountID: active.id, now: now)
        XCTAssertEqual(r, .transient)
        XCTAssertEqual(mock.callCount, 0)
        XCTAssertFalse(reauth(fallback.id), "누가 주인인지 모르므로 마킹하지 않는다")
    }

    /// 응답으로 불일치가 드러나면 회전본을 버리지 않고, 그 조직의 비활성 프로필에 넘긴다 — 서버는 이미
    /// 이전 토큰을 소비했으므로 버리면 살아남는 사본이 없다(리뷰 P1).
    func testResponseMismatchHandsRotationToOwningProfile() async throws {
        let mixed = try orgFallback(org: "org-max")   // blob만으로는 섞였는지 모르는 저장본
        let ownerBlob = Data(#"{"claudeAiOauth":{"accessToken":"OAT","refreshToken":"DEAD","expiresAt":1,"refreshTokenExpiresAt":\#(futureRteMs),"subscriptionType":"team"}}"#.utf8)
        let owner = try store.upsertProfile(nickname: "team-owner", snapshot: CredentialsSnapshot(
            keychainBlob: ownerBlob, credentialsFileData: ownerBlob,
            oauthAccountJSON: Data(#"{"emailAddress":"t@x.com","organizationName":"acme","organizationUuid":"org-team"}"#.utf8)))
        try store.setNeedsReauth(owner.id, true)   // 계보를 빼앗겨 죽어 있던 주인

        let r = await FallbackAuthChecker(store: store, refresher: MockRefresher(.success(tokens(org: "org-team"))))
            .check(mixed.id, activeAccountID: active.id, now: now)

        XCTAssertEqual(r, .organizationMismatch)
        XCTAssertTrue(reauth(mixed.id))
        let ownerSnap = try XCTUnwrap(store.secret(for: owner.id))
        XCTAssertEqual(CredentialBlob.refreshToken(from: ownerSnap.keychainBlob), "NRT", "회전본은 주인에게")
        XCTAssertEqual(ClaudeConfigIO.identity(fromSnapshot: ownerSnap)?.organizationUuid, "org-team",
                       "주인의 oauthAccount는 그대로")
        XCTAssertFalse(reauth(owner.id))
    }

    /// preflight를 거치지 않는 전환은 진행 중 refresh가 회전본을 저장할 때까지 기다린다(리뷰 P2).
    func testWaitForInFlightRefreshReturnsAfterRotationIsStored() async throws {
        let gated = GatedRefresher(tokens: tokens(org: nil))
        let checker = FallbackAuthChecker(store: store, refresher: gated)
        let id = fallback.id, activeID = active.id, ts = now
        let entered = expectation(description: "refresh entered")
        gated.onEnter = { entered.fulfill() }
        let refresh = Task { await checker.check(id, activeAccountID: activeID, now: ts) }
        await fulfillment(of: [entered], timeout: 2)

        let waited = expectation(description: "wait returned")
        let waiter = Task { await checker.waitForInFlightRefresh(of: id); waited.fulfill() }
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: id)).keychainBlob), "FRT")
        gated.release()
        await fulfillment(of: [waited], timeout: 2)
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: id)).keychainBlob), "NRT",
                       "기다린 뒤에는 회전본이 저장돼 있다 — 전환이 이걸 설치한다")
        _ = await refresh.value; _ = await waiter.value
        await checker.waitForInFlightRefresh(of: id)   // 진행 중이 없으면 바로 돌아온다
    }

    /// HTTP 왕복 사이에 이 계정이 활성이 됐으면(CLI 전환 등) 라이브가 진실이다 — 저장하지 않는다.
    /// 앱 안의 전환은 `waitForInFlightRefresh`로 이 창을 닫으므로, 이 경로는 CLI 전환(다른 프로세스)의
    /// 알려진 한계다. 소비된 "FRT"가 남는 것이 현재 동작이다.
    func testRotationIsNotStoredWhenAccountBecameActive() async throws {
        let gated = GatedRefresher(tokens: tokens(org: nil))
        let checker = FallbackAuthChecker(store: store, refresher: gated)
        let id = fallback.id, activeID = active.id, ts = now
        let entered = expectation(description: "refresh entered")
        gated.onEnter = { entered.fulfill() }
        let task = Task { await checker.check(id, activeAccountID: activeID, now: ts) }
        await fulfillment(of: [entered], timeout: 2)

        try store.setActive(fallback.id)
        gated.release()

        let r = await task.value
        XCTAssertEqual(r, .transient)
        XCTAssertEqual(CredentialBlob.refreshToken(from: try XCTUnwrap(store.secret(for: fallback.id)).keychainBlob), "FRT")
    }
}
