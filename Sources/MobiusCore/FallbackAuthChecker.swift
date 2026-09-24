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
    /// 저장 스냅샷 자체의 토큰과 oauthAccount가 서로 다른 조직 종류를 가리킨다(네트워크 0 판정).
    /// refresh하지 않고 재로그인 필요로 마킹한다. `organizationMismatch`와 나눈 이유는 알림 담당이
    /// 다르기 때문이다 — `locallyDead`/`dead`처럼 로컬 판정은 팝오버의 로컬 검증이 알린다.
    case mixedSnapshot
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
        // 네트워크 0: 저장 스냅샷 자체의 토큰과 신원이 어긋나 있으면(토큰은 Team, oauthAccount는 Max)
        // 이미 섞인 카드다. **refresh하기 전에** 잡아야 한다 — 섞인 저장본은 대개 라이브나 다른 카드와
        // 같은 refresh 토큰을 쥐고 있어서, 여기서 회전하면 올바른 쪽의 계보까지 끊긴다(실패 기록 24, 리뷰 P1).
        if ClaudeConfigIO.liveSnapshotVerdict(snap) == .organizationMismatch {
            try? store.setNeedsReauth(id, true); return .mixedSnapshot
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
        // 다른 Claude 프로필의 저장본이 **같은 refresh 토큰**을 쥐고 있으면 refresh하지 않는다. 한 계보를
        // 두 프로필이 나눠 가진 상태 자체가 오염이고(실패 기록 24), 회전하면 다른 쪽 사본이 invalid_grant가
        // 된다. 누가 주인인지는 여기서 가릴 수 없으므로 마킹 없이 판정을 미룬다. 위의 스냅샷 판정이 못 잡는
        // 경우(같은 종류의 두 조직, subscriptionType이 없는 옛 계보)를 막는 자리다.
        if sharesRefreshToken(rt, exceptProfile: id) { return .transient }
        let scopes = CredentialBlob.scopes(from: snap.keychainBlob)
        do {
            let tokens = try await refresher.refresh(refreshToken: rt, scopes: scopes, now: now)
            // 여기 도달 = old refresh 토큰은 서버에서 소비됨. 새 토큰을 반드시 저장해야 한다.
            guard let newSnap = snap.applyingRefreshedTokens(tokens) else {
                try? store.setNeedsReauth(id, true); return .storeFailed
            }
            let profileOrg = store.file.accounts.first(where: { $0.id == id })?.organizationUuid ?? ""
            let foreignOrg = tokens.organizationUuid.flatMap {
                !profileOrg.isEmpty && $0 != profileOrg ? $0 : nil
            }
            // ★ 저장은 credential lock 안에서 다시 확인한 뒤에 한다(Codex 경로와 같은 규칙).
            //   HTTP 왕복 사이에 (1) 재로그인·되저장이 이 프로필에 새 스냅샷을 썼으면 옛 계보의
            //   회전본으로 덮지 않고, (2) 이 계정이 활성이 됐으면 라이브(~/.claude)를 건드리지 않는다.
            //   앱 안의 전환은 전부 진행 중 refresh를 기다린 뒤 스냅샷을 설치하므로(preflight 합류,
            //   `waitForInFlightRefresh`) (2)는 다른 프로세스인 CLI 전환에서만 생긴다. 이때 라이브에
            //   설치된 토큰은 방금 소비된 것이라 회전본을 버리면 계보가 끊기지만, 라이브에 쓸 수단이
            //   이 타입에 없다 — 알려진 한계로 둔다. 둘 다 판정 보류(transient)다.
            let outcome = store.withCredentialLock(id) { () -> FallbackCheckResult in
                guard (try? store.secret(for: id)) == snap,
                      store.file.activeByProvider[.claude] != id else { return .transient }
                // 응답이 말하는 조직이 이 프로필의 조직과 다르면 저장할 자리가 아니다. 추가 호출 없이
                // 오염을 잡는 지점이고, 같은 종류의 두 조직(Team과 다른 Team)도 여기서는 갈린다.
                if foreignOrg != nil {
                    try? store.setNeedsReauth(id, true); return .organizationMismatch
                }
                do {
                    try store.setSecret(newSnap, for: id)     // 원자 저장(temp→rename)
                    try? store.setNeedsReauth(id, false)      // 살아있음 → 딱지 해제
                    return .refreshedAlive
                } catch {
                    // 새 토큰 유실 → old RT는 이미 죽음 → 재로그인이 복구 경로
                    try? store.setNeedsReauth(id, true); return .storeFailed
                }
            }
            // 락을 놓은 뒤에 넘긴다 — 두 프로필의 credential lock을 겹쳐 잡지 않는다.
            if outcome == .organizationMismatch, let foreignOrg {
                handOverRotation(tokens, organizationUuid: foreignOrg, from: id)
            }
            return outcome
        } catch TokenRefresherError.invalidGrant {
            try? store.setNeedsReauth(id, true); return .dead
        } catch {
            return .transient   // 네트워크/5xx — 죽음으로 단정하지 않음
        }
    }

    /// 이 계정의 진행 중 refresh가 있으면 끝날 때까지 기다린다(새 refresh는 쏘지 않는다).
    /// preflight를 거치지 않는 전환(primary 자동 복귀, 재로그인 필요 계정의 수동 전환)이 **회전 직전의
    /// 스냅샷**을 라이브에 설치하지 않게 한다 — 그 토큰은 진행 중 refresh가 곧 소비해 죽는다(리뷰 P2).
    public func waitForInFlightRefresh(of id: UUID) async {
        let task = withLock { inFlight[id] }
        _ = await task?.value
    }

    /// `id` 말고 다른 Claude 프로필의 저장본이 이 refresh 토큰을 쥐고 있는가.
    /// 비밀 **파일이 있는** 계정만 읽는다(stat 게이트 — 구버전 Keychain 폴백 승인창을 타지 않는다).
    private func sharesRefreshToken(_ rt: String, exceptProfile id: UUID) -> Bool {
        store.file.accounts.contains { other in
            guard other.provider == .claude, other.id != id,
                  FileManager.default.fileExists(atPath: store.env.secretFile(for: other.id).path),
                  let theirs = try? store.secret(for: other.id) else { return false }
            return CredentialBlob.refreshToken(from: theirs.keychainBlob) == rt
        }
    }

    /// 회전본의 진짜 주인에게 넘긴다 — 응답이 말하는 조직의 같은 이메일 프로필이 **정확히 하나**이고
    /// 비활성이면, 그 프로필의 스냅샷(자기 oauthAccount 유지)에 새 토큰을 반영한다. 서버는 이미 이전
    /// 토큰을 소비했으므로, 버리면 이 계보의 살아남는 사본이 하나도 없다(리뷰 P1). 주인이 활성이면
    /// 라이브가 그 계정을 관리하므로 넘기지 않는다. 주인이 없거나 여럿이면 버린다(모호하면 손대지 않는다).
    private func handOverRotation(_ tokens: RefreshedTokens, organizationUuid org: String, from id: UUID) {
        guard let source = store.file.accounts.first(where: { $0.id == id }) else { return }
        let owners = store.file.accounts.filter {
            $0.provider == .claude && $0.id != id
                && $0.emailAddress == source.emailAddress && $0.organizationUuid == org
        }
        guard owners.count == 1, let owner = owners.first else { return }
        store.withCredentialLock(owner.id) {
            guard store.file.activeByProvider[.claude] != owner.id,
                  let ownerSnap = try? store.secret(for: owner.id),
                  let rebuilt = ownerSnap.applyingRefreshedTokens(tokens),
                  (try? store.setSecret(rebuilt, for: owner.id)) != nil else { return }
            try? store.setNeedsReauth(owner.id, false)
        }
    }
}
