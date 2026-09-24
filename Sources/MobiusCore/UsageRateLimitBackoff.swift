import Foundation

/// 사용량 엔드포인트의 429(요청 제한)를 **계정별로** 기억해, 서버가 준 대기 시간 동안 그 계정의
/// 조회를 쉰다(실패 기록 25).
///
/// 이 엔드포인트는 같은 계정을 부르는 모든 클라이언트(Mobius, 상태줄 도구, claude 자신의
/// `/usage`·한도 도달 시 조회)가 함께 쓰는 제한에 걸린다. 제한 중에 다시 부르면 값은 못 얻고
/// 제한만 길어질 수 있으므로, 팝오버·5분 폴링·한도 검증·후보 확인이 모두 이 표를 먼저 본다.
///
/// 계정 단위인 이유: 제한은 토큰(계정)에 걸린다. 한 계정이 막혔다고 다른 계정의 조회까지
/// 쉬면, 멀쩡한 폴백의 게이지와 전환 후보 확인이 함께 멈춘다.
///
/// 앱 재시작 때는 비운다(인메모리). 재시작 직후 한 번 더 부르고 다시 429를 받으면 그때 또
/// 기록되므로, 영속화의 이득이 호출 한 번뿐이다.
public struct UsageRateLimitBackoff: Equatable, Sendable {
    /// `Retry-After`가 없을 때 기다리는 시간.
    public static let defaultWait: TimeInterval = 5 * 60
    /// 너무 짧은 값(0, 1초)으로 곧바로 다시 부르지 않게 하는 하한.
    public static let minWait: TimeInterval = 30
    /// 서버 값이 비정상적으로 길 때의 상한. 실측 최대는 3600초였다.
    public static let maxWait: TimeInterval = 60 * 60

    public private(set) var retryAt: [UUID: Date] = [:]

    public init() {}

    /// 이 계정의 조회를 지금 쉬어야 하는가.
    public func isBlocked(_ id: UUID, now: Date) -> Bool {
        retryDate(id, now: now) != nil
    }

    /// 다시 조회해도 되는 시각. 제한 중이 아니면 nil.
    public func retryDate(_ id: UUID, now: Date) -> Date? {
        guard let until = retryAt[id], now < until else { return nil }
        return until
    }

    /// 429를 받았다. 이미 더 늦은 시각까지 막혀 있으면 앞당기지 않는다.
    public mutating func recordRateLimited(_ id: UUID, retryAfter: TimeInterval?, now: Date) {
        let wait = min(max(retryAfter ?? Self.defaultWait, Self.minWait), Self.maxWait)
        let until = now.addingTimeInterval(wait)
        if let current = retryAt[id], current >= until { return }
        retryAt[id] = until
    }

    /// 조회가 성공했다 — 제한 기록을 지운다.
    public mutating func recordSuccess(_ id: UUID) {
        retryAt[id] = nil
    }
}
