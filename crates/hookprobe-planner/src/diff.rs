//! Line-level diff between two plan-as-diff `Vec<String>`s (the exact shape
//! `hookprobe_manifest::aegis::ReconcileResult::plan` already produces). A plain LCS diff —
//! deliberately hand-rolled rather than pulling in a diff crate: the reconciler's plan is a
//! handful of lines (one per domain — WAN/Wi-Fi/Fabric/Microseg/LAN/NAC/Inspect/Enforce/Trust), so
//! an O(n·m) dynamic-programming LCS is instant and needs zero new dependencies.

use crate::schema::DiffLine;

/// Longest-common-subsequence diff of two line lists, rendered as [`DiffLine`]s in a natural
/// reading order (unchanged/removed lines from `before` interleaved with new `Added` lines from
/// `after`, in the position the LCS backtrack visits them).
pub fn diff_plan(before: &[String], after: &[String]) -> Vec<DiffLine> {
    let n = before.len();
    let m = after.len();
    // dp[i][j] = length of the LCS of before[i..] and after[j..].
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if before[i] == after[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut out = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if before[i] == after[j] {
            out.push(DiffLine::Unchanged(before[i].clone()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push(DiffLine::Removed(before[i].clone()));
            i += 1;
        } else {
            out.push(DiffLine::Added(after[j].clone()));
            j += 1;
        }
    }
    while i < n {
        out.push(DiffLine::Removed(before[i].clone()));
        i += 1;
    }
    while j < m {
        out.push(DiffLine::Added(after[j].clone()));
        j += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_plans_are_all_unchanged() {
        let before = v(&["WAN · ok", "Wi-Fi · idle"]);
        let after = before.clone();
        let d = diff_plan(&before, &after);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|l| matches!(l, DiffLine::Unchanged(_))));
    }

    #[test]
    fn a_changed_line_shows_as_removed_then_added() {
        let before = v(&["WAN · ok", "NAC · 0 devices"]);
        let after = v(&["WAN · ok", "NAC · 1 device (camera → isolated)"]);
        let d = diff_plan(&before, &after);
        assert_eq!(d[0], DiffLine::Unchanged("WAN · ok".to_string()));
        assert!(d.iter().any(|l| matches!(l, DiffLine::Removed(s) if s == "NAC · 0 devices")));
        assert!(d.iter().any(|l| matches!(l, DiffLine::Added(s) if s.contains("isolated"))));
    }

    #[test]
    fn a_purely_added_line_has_no_removed_entries() {
        let before = v(&["WAN · ok"]);
        let after = v(&["WAN · ok", "NAC · 1 device (camera → isolated)"]);
        let d = diff_plan(&before, &after);
        assert!(!d.iter().any(|l| matches!(l, DiffLine::Removed(_))));
        assert!(matches!(&d[1], DiffLine::Added(s) if s.contains("isolated")));
    }

    #[test]
    fn empty_before_is_all_additions() {
        let before: Vec<String> = vec![];
        let after = v(&["a", "b"]);
        let d = diff_plan(&before, &after);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|l| matches!(l, DiffLine::Added(_))));
    }
}
