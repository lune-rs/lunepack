//! Time helpers. Every animation of the screens is a pure function of the frame time the caller
//! supplies and of the instants the model recorded; nothing here reads a clock.

use std::time::Duration;

use lune_ui::motion::{Easing, MotionTier};

/// Linear progress of `t` through `since .. since + ms`, clamped to 0..1.
pub fn progress(t: Duration, since: Duration, ms: u64) -> f32 {
    if ms == 0 {
        return if t >= since { 1.0 } else { 0.0 };
    }
    let into = t.saturating_sub(since);
    (into.as_secs_f32() / (ms as f32 / 1000.0)).clamp(0.0, 1.0)
}

/// `ease` of the progress of `t` through `since .. since + ms`.
pub fn eased(ease: Easing, t: Duration, since: Duration, ms: u64) -> f32 {
    ease.eval(progress(t, since, ms))
}

/// Whether a run of `ms` from `since` is still moving at `t`.
pub fn running(t: Duration, since: Duration, ms: u64) -> bool {
    t < since.saturating_add(Duration::from_millis(ms))
}

/// Whether movement (slides, scale, drawing-in) is allowed: Full only; Reduced keeps colour and
/// opacity, Off snaps.
pub fn moves(tier: MotionTier) -> bool {
    tier == MotionTier::Full
}

/// Whether anything animates at all.
pub fn animates(tier: MotionTier) -> bool {
    tier != MotionTier::Off
}

/// `frac(t / period)` in 0..1.
pub fn phase(t: Duration, period: Duration) -> f32 {
    let into = t.as_nanos() % period.as_nanos().max(1);
    (into as f64 / period.as_nanos().max(1) as f64) as f32
}
