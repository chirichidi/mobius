import Foundation

/// 폴백(비활성) 계정의 **로그인 생사를 미리 판정**한다 — 자동 fallback이 실제로 넘어가기 전에
/// 그 계정이 쓸 수 있는지 알기 위함. 판정 신호는 **refresh 결과**다(모호한 usage 401 아님):
///   - 로컬 선검사(네트워크 0): `refreshTokenExpiresAt`가 지났으면 죽음 확정
///   - refresh 성공 → 살아있음(+새 토큰 원자 저장 → usage도 살아남)
///   - invalid_grant → 죽음 확정 → 재로그인 필요
///   - 네트워크/5xx → 일시적(죽음으로 단정 안 함)
///
/// ★ 활성(라이브) 계정은 **절대** refresh하지 않는다 — claude가 관리하는 토큰을 로테이션하면
///   실행 중 세션이 깨진다. 첫 guard로 차단한다.
/// ★ 원자성: refresh가 성공하면 old refresh 토큰은 서버에서 이미 소비된다. 새 토큰 저장에
///   실패하면 계정이 벽돌이 되므로, 저장 실패 시 needsReauth로 마킹해 재로그인으로 복구시킨다.

public enum FallbackCheckResult: Equatable, Sendable {
    case notFallback     // 활성 계정 — 건드리지 않음
    case noSecret        // 저장 스냅샷 없음
    case noRefreshToken  // 스냅샷에 refresh 토큰 없음 → 재로그인 필요
    case locallyDead     // refreshTokenExpiresAt 지남(네트워크 0) → 재로그인 필요
    case refreshedAlive  // refresh 성공 + 새 스냅샷 원자 저장
    case dead            // invalid_grant → 재로그인 필요
    case transient       // 네트워크/5xx → 마킹 안 함(재시도)
    case storeFailed     // refresh 성공했으나 저장 실패 → 새 토큰 유실 → 재로그인 필요로 마킹
    /// refresh 응답의 조직이 프로필의 조직과 다르다 — 저장 스냅샷이 **남의 조직 토큰**을 들고
    /// 있었다(실패 기록 24). 회전본은 저장하지 않고 재로그인 필요로 마킹한다: 그 토큰을 이
    /// 프로필에 두면 카드가 다른 조직의 사용량을 보여 주고, 전환하면 다른 조직으로 로그인된다.
    case organizationMismatch
}

public final class FallbackAuthChecker: @unchecked Sendable {
    let store: AccountStore
    let refresher: TokenRefresher
    /// 계정별 진행 중 네트워크 refresh — 같은 계정의 동시 check는 새 refresh를 쏘지 않고
    /// 이 태스크의 결과에 **합류**한다. 동시 이중 refresh는 회전(rotation) 때문에 늦은 쪽이
    /// 이미 소비된 refresh 토큰으로 invalid_grant를 받아 **살아있는 계정을 needsReauth로
    /// 오마킹**한다 (예: 스윕이 폴백을 갱신하는 1~2초 사이에 사용자가 그 계정을 클릭 →
    /// preflight와 충돌). 락은 딕셔너리 접근에만 쓰고 await를 가로지르지 않는다.
    private var inFlight: [UUID: Task<FallbackCheckResult, Never>] = [:]
    private var joinedCount = 0
    private let lock = NSLock()

    public init(store: AccountStore, refresher: TokenRefresher = OAuthTokenRefresher()) {
        self.store = store
        self.refresher = refresher
    }

    /// 합류가 실제로 일어난 횟수 (테스트 관측용)
    var coalescedJoins: Int { withLock { joinedCount } }

    /// async 컨텍스트에서 NSLock을 직접 못 쓰므로(SE-0340) 동기 구간으로 감싼다.
    /// body는 절대 suspend하지 않는 짧은 딕셔너리 접근만 담는다.
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    /// 폴백 하나를 검증하고 부작용(스냅샷 저장 / needsReauth)을 적용한다.
    /// 값싼 조건(활성 여부 → 스냅샷 → refresh 토큰 → 로컬 만료)을 먼저 통과시키고
    /// **네트워크 refresh는 정말 필요할 때만** 호출한다 (계정 리스크 최소화).
    /// allowNetwork=false면 **네트워크 0 로컬 검사만** 한다(팝오버용) — 빈/만료 refresh 토큰만
    /// 즉시 플래그하고, 실제 refresh가 필요한 경우엔 .transient로 물러난다.
    /// allowNetwork=true면 필요 시 실제 refresh까지 한다(자동 폴백 전환 직전용).
    @discardableResult
    public func check(_ id: UUID, activeAccountID: UUID?, now: Date = Date(),
                      allowNetwork: Bool = true) async -> FallbackCheckResult {
        guard id != activeAccountID else { return .notFallback }           // 활성 절대 제외
        guard let snap = try? store.secret(for: id) else { return .noSecret }
        guard CredentialBlob.refreshToken(from: snap.keychainBlob) != nil else {
            try? store.setNeedsReauth(id, true); return .noRefreshToken
        }
        // 네트워크 0: refresh 토큰 자체가 시간상 만료 → 죽음 확정
        if CredentialBlob.isRefreshTokenExpired(blob: snap.keychainBlob, now: now) {
            try? store.setNeedsReauth(id, true); return .locallyDead
        }
        guard allowNetwork else { return .transient }   // 로컬 검사 통과 — 네트워크는 생략

        // 같은 계정의 네트워크 refresh는 동시에 1건만 — 진행 중이면 그 결과에 합류한다.
        let (task, joined): (Task<FallbackCheckResult, Never>, Bool) = withLock {
            if let existing = inFlight[id] {
                joinedCount += 1
                return (existing, true)
            }
            let t = Task { await self.refreshAndStore(id, now: now) }
            inFlight[id] = t
            return (t, false)
        }
        let result = await task.value
        if !joined { withLock { inFlight[id] = nil } }   // 생성자만 게이트 해제
        return result
    }

    /// 실제 refresh + 회전 토큰 원자 저장 — inFlight 게이트 안에서만 호출된다.
    /// 스냅샷은 여기서 **다시 읽는다**: 게이트 밖(check 상단)에서 읽은 토큰은 직전에 끝난
    /// 다른 refresh의 회전으로 이미 낡았을 수 있다 (낡은 토큰 전송 = invalid_grant 오마킹).
    private func refreshAndStore(_ id: UUID, now: Date) async -> FallbackCheckResult {
        guard let snap = try? store.secret(for: id) else { return .noSecret }
        guard let rt = CredentialBlob.refreshToken(from: snap.keychainBlob) else {
            try? store.setNeedsReauth(id, true); return .noRefreshToken
        }
        let scopes = CredentialBlob.scopes(from: snap.keychainBlob)
        do {
            let tokens = try await refresher.refresh(refreshToken: rt, scopes: scopes, now: now)
            // 여기 도달 = old refresh 토큰은 서버에서 소비됨. 새 토큰을 반드시 저장해야 한다.
            // 단 응답이 말하는 조직이 이 프로필의 조직과 다르면 저장할 자리가 아니다 — 추가 호출 없이
            // 오염을 잡는 유일한 지점이고, 같은 종류의 두 조직(Team과 다른 Team)도 여기서는 갈린다.
            let profileOrg = store.file.accounts.first(where: { $0.id == id })?.organizationUuid ?? ""
            if let tokenOrg = tokens.organizationUuid, !profileOrg.isEmpty, tokenOrg != profileOrg {
                try? store.setNeedsReauth(id, true); return .organizationMismatch
            }
            guard let newSnap = snap.applyingRefreshedTokens(tokens) else {
                try? store.setNeedsReauth(id, true); return .storeFailed
            }
            // ★ 저장은 credential lock 안에서 다시 확인한 뒤에 한다(Codex 경로와 같은 규칙).
            //   HTTP 왕복 사이에 (1) 재로그인·되저장이 이 프로필에 새 스냅샷을 썼으면 옛 계보의
            //   회전본으로 덮지 않고, (2) 이 계정이 활성이 됐으면 라이브(~/.claude)가 진실이므로
            //   손대지 않는다. 앱 안의 전환은 preflight가 진행 중 refresh에 합류해 여기까지 오지
            //   않지만, CLI 전환은 다른 프로세스라 합류가 없다. 둘 다 판정 보류(transient)다.
            return store.withCredentialLock(id) { () -> FallbackCheckResult in
                guard (try? store.secret(for: id)) == snap,
                      store.file.activeByProvider[.claude] != id else { return .transient }
                do {
                    try store.setSecret(newSnap, for: id)     // 원자 저장(temp→rename)
                    try? store.setNeedsReauth(id, false)      // 살아있음 → 딱지 해제
                    return .refreshedAlive
                } catch {
                    // 새 토큰 유실 → old RT는 이미 죽음 → 재로그인이 복구 경로
                    try? store.setNeedsReauth(id, true); return .storeFailed
                }
            }
        } catch TokenRefresherError.invalidGrant {
            try? store.setNeedsReauth(id, true); return .dead
        } catch {
            return .transient   // 네트워크/5xx — 죽음으로 단정하지 않음
        }
    }
}
