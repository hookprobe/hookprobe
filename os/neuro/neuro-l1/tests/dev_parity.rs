// SPDX-License-Identifier: AGPL-3.0-only
//! Doc 53 R10: the `dev=` token equals the Python reference (tools/neuro-research/dev_token.py) bit for bit, on the
//! reference u8 features of every window in tests/fixture.txt. tests/dev_fixture.txt is written by
//! `dev_token.py vectors tests/fixture.txt tests/dev_fixture.txt`.
use neuro_l1::{deviations, write_dev_token};

fn q_of(field: &str) -> [u8; 28] {
    let v: Vec<u8> = field.split(',').map(|x| x.parse().unwrap()).collect();
    v.try_into().unwrap()
}

#[test]
fn dev_token_equals_python_reference() {
    let want: Vec<(&str, &str)> = include_str!("dev_fixture.txt")
        .lines()
        .map(|l| l.split_once(' ').unwrap())
        .collect();
    let mut got = Vec::new();
    for line in include_str!("fixture.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] == "W" || f[0] == "E" {
            let mut buf = [0u8; 64];
            let n = write_dev_token(&q_of(f[3]), &mut buf);
            got.push((f[1].to_string(), String::from_utf8(buf[..n].to_vec()).unwrap()));
        }
    }
    assert_eq!(got.len(), want.len());
    for ((gid, gtok), (wid, wtok)) in got.iter().zip(&want) {
        assert_eq!(gid, wid);
        assert_eq!(gtok, wtok, "window {gid}");
    }
}

#[test]
fn token_fits_and_is_ordered() {
    // every corner of the u8 cube for the longest names still fits 64 bytes; order is by |z| descending
    for q in [[0u8; 28], [255u8; 28], [128u8; 28]] {
        let mut buf = [0u8; 64];
        let n = write_dev_token(&q, &mut buf);
        assert!(n > 0 && n <= 64);
        let d = deviations(&q);
        assert!(d[0].1.unsigned_abs() >= d[1].1.unsigned_abs() && d[1].1.unsigned_abs() >= d[2].1.unsigned_abs());
    }
}
