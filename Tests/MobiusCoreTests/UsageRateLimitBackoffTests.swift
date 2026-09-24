import XCTest
@testable import MobiusCore

/// 사용량 엔드포인트 429의 계정별 대기 시각(실패 기록 25).
final class UsageRateLimitBackoffTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_790_000_000)
    let a = UUID(), b = UUID()

    func testServerRetryAfterIsHonoredPerAccount() {
        var backoff = UsageRateLimitBackoff()
        backoff.recordRateLimited(a, retryAfter: 126, now: now)

        XCTAssertTrue(backoff.isBlocked(a, now: now.addingTimeInterval(125)))
        XCTAssertFalse(backoff.isBlocked(a, now: now.addingTimeInterval(126)), "대기 시각이 지나면 다시 부른다")
        XCTAssertFalse(backoff.isBlocked(b, now: now), "다른 계정의 조회는 막지 않는다")
        XCTAssertEqual(backoff.retryDate(a, now: now), now.addingTimeInterval(126))
        XCTAssertNil(backoff.retryDate(a, now: now.addingTimeInterval(200)))
    }

    func testMissingOrExtremeRetryAfterIsClamped() {
        var backoff = UsageRateLimitBackoff()
        backoff.recordRateLimited(a, retryAfter: nil, now: now)
        XCTAssertEqual(backoff.retryDate(a, now: now), now.addingTimeInterval(UsageRateLimitBackoff.defaultWait))

        backoff.recordRateLimited(b, retryAfter: 0, now: now)
        XCTAssertEqual(backoff.retryDate(b, now: now), now.addingTimeInterval(UsageRateLimitBackoff.minWait),
                       "0초로 곧바로 다시 부르지 않는다")

        var long = UsageRateLimitBackoff()
        long.recordRateLimited(a, retryAfter: 24 * 3600, now: now)
        XCTAssertEqual(long.retryDate(a, now: now), now.addingTimeInterval(UsageRateLimitBackoff.maxWait))
    }

    /// 한 계정에 여러 경로가 거의 동시에 429를 받으면, 짧은 값이 긴 대기를 앞당기면 안 된다.
    func testShorterRetryAfterDoesNotShortenExistingWait() {
        var backoff = UsageRateLimitBackoff()
        backoff.recordRateLimited(a, retryAfter: 3600, now: now)
        backoff.recordRateLimited(a, retryAfter: 60, now: now.addingTimeInterval(10))
        XCTAssertEqual(backoff.retryDate(a, now: now), now.addingTimeInterval(3600))
        backoff.recordRateLimited(a, retryAfter: 3600, now: now.addingTimeInterval(100))
        XCTAssertEqual(backoff.retryDate(a, now: now), now.addingTimeInterval(3700), "더 늦은 값으로는 늘린다")
    }

    func testSuccessClearsTheWait() {
        var backoff = UsageRateLimitBackoff()
        backoff.recordRateLimited(a, retryAfter: 600, now: now)
        backoff.recordSuccess(a)
        XCTAssertFalse(backoff.isBlocked(a, now: now))
    }
}
