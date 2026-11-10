//! Per-device behaviour baseline (production phase 4 — the "IoT baseline").
//!
//! A single-purpose device (a camera, a smart plug, a TV, a printer — device identification's category) talks
//! to the same few internet services for its whole life. heqk learns that set — (protocol, destination port)
//! of its outbound connection attempts — during a learning window after it is first seen; afterwards a NEVER
//! seen service (a plug that suddenly opens SSH, SMTP or a crypto-mining pool port) raises rule 128
//! "device behaviour change". Observe-only (a Behavioral finding: never a drop), at most one alert per
//! device per hour. General-purpose devices (phones, laptops) are never baselined: their port set is open by
//! nature — and a device that uses more than `PORTS` distinct services while learning is treated as one.
//!
//! Bounded: `DEVS` devices (the least recently seen is replaced), `PORTS` services each, no allocation.

pub const RULE_BASELINE: u16 = 128;
/// Learning window after a device is first seen.
pub const LEARN_SECS: u64 = 24 * 3600;
const REALERT_SECS: u64 = 3600;
const DEVS: usize = 64;
const PORTS: usize = 16;

#[derive(Clone, Copy)]
struct Dev {
    ip: u32,
    first: u64,
    last: u64,
    /// 0 = not classified yet, 1 = single-purpose (baselined), 2 = general-purpose (never baselined)
    kind: u8,
    n: u8,
    ports: [(u8, u16); PORTS],
    last_alert: u64,
}
const DEV0: Dev = Dev { ip: 0, first: 0, last: 0, kind: 0, n: 0, ports: [(0, 0); PORTS], last_alert: 0 };
static mut T: [Dev; DEVS] = [DEV0; DEVS];

/// Device-identification categories that are single-purpose by nature.
pub fn is_single_purpose(category: &str) -> bool {
    matches!(category, "iot" | "camera" | "tv" | "printer" | "speaker" | "thermostat" | "plug" | "media" | "doorbell")
}

/// One outbound connection attempt by `ip` (proto 6 = TCP SYN, 17 = UDP) to `dport` at `now` (seconds).
/// `single_purpose` is asked once per device (its identification). Returns true when rule 128 fired.
pub fn observe(ip: u32, single_purpose: impl FnOnce() -> bool, proto: u8, dport: u16, now: u64) -> bool {
    if ip == 0 {
        return false;
    }
    let t = unsafe { &mut *core::ptr::addr_of_mut!(T) };
    let i = match t.iter().position(|d| d.ip == ip && d.first != 0) {
        Some(i) => i,
        None => {
            let i = (0..DEVS).min_by_key(|&k| t[k].last).unwrap_or(0);
            t[i] = Dev { ip, first: now.max(1), last: now.max(1), ..DEV0 };
            i
        }
    };
    let d = &mut t[i];
    d.last = now.max(1);
    if d.kind == 0 {
        d.kind = if single_purpose() { 1 } else { 2 };
    }
    if d.kind != 1 {
        return false;
    }
    let known = d.ports[..d.n as usize].iter().any(|&(p, q)| p == proto && q == dport);
    if known {
        return false;
    }
    if now.saturating_sub(d.first) < LEARN_SECS {
        if (d.n as usize) < PORTS {
            d.ports[d.n as usize] = (proto, dport);
            d.n += 1;
        } else {
            d.kind = 2; // too many services to be single-purpose: never baselined
        }
        return false;
    }
    // learned: a service this device never used
    if (d.n as usize) < PORTS {
        d.ports[d.n as usize] = (proto, dport); // one alert per new service
        d.n += 1;
    }
    if d.last_alert != 0 && now.saturating_sub(d.last_alert) < REALERT_SECS {
        return false;
    }
    d.last_alert = now.max(1);
    crate::rules::baseline_change(ip);
    true
}

/// Clear the table (self-tests).
pub fn reset() {
    unsafe { *core::ptr::addr_of_mut!(T) = [DEV0; DEVS] };
}

/// `[P-devbase]`
pub fn selftest() -> bool {
    reset();
    let cam = u32::from_be_bytes([10, 99, 0, 80]);
    let phone = u32::from_be_bytes([10, 99, 0, 81]);
    let busy = u32::from_be_bytes([10, 99, 0, 82]);
    let t0 = 1_000;
    // learning: the camera uses its cloud (443), NTP (123/udp) and MQTT (8883)
    let quiet_learning = !observe(cam, || true, 6, 443, t0)
        && !observe(cam, || true, 17, 123, t0 + 60)
        && !observe(cam, || true, 6, 8883, t0 + 3600)
        && !observe(cam, || true, 6, 22, t0 + 7200); // still learning: even SSH is just learned
    let after = t0 + LEARN_SECS + 10;
    let known_ok = !observe(cam, || true, 6, 443, after) && !observe(cam, || true, 17, 123, after + 1);
    let new_fires = observe(cam, || true, 6, 25, after + 2); // SMTP from a camera: behaviour change
    let capped = !observe(cam, || true, 6, 3333, after + 60); // another new port within the hour: capped
    let again = observe(cam, || true, 6, 4444, after + 60 + REALERT_SECS); // next hour: alerts again
    // a phone (general-purpose) is never baselined
    let phone_quiet = (0..40u16).all(|p| !observe(phone, || false, 6, 1000 + p, after + p as u64));
    // a "single-purpose" device that used 20 services while learning is treated as general-purpose
    for p in 0..20u16 {
        let _ = observe(busy, || true, 6, 2000 + p, t0 + p as u64);
    }
    let busy_quiet = !observe(busy, || true, 6, 9999, after + 5);
    reset();
    let pass = quiet_learning && known_ok && new_fires && capped && again && phone_quiet && busy_quiet;
    arch_aarch64::_print(format_args!(
        " [P-devbase] {} — per-device behaviour baseline (phase 4, rule 128, observe-only): learning window silent={} learned services stay quiet={} a new service from a camera fires={} capped to one alert an hour={} alerts again next hour={} a phone is never baselined={} a device with 20 services while learning is never baselined={}\n",
        if pass { "PASS" } else { "FAIL" }, quiet_learning, known_ok, new_fires, capped, again, phone_quiet, busy_quiet));
    pass
}
