//! CLI integration tests for `mip3-deploy` via `assert_cmd`.
//!
//! These tests only exercise the local (no-network) paths:
//!
//! - `templates list` — enumerates the 4 preset names.
//! - `templates show <preset>` — prints JSON / human details.
//! - `perp <preset> --name ... --dry-run` — prints the 8-action sequence
//!   without making any HTTP call.
//!
//! Network-bound subcommands (`bid`, `check-credit`, real `perp` submit) are
//! covered by the per-module unit tests; this file is intentionally focused
//! on the CLI dispatch + output rendering layer.

#![cfg(feature = "cli")]

use assert_cmd::Command;

const BIN: &str = "mip3-deploy";

#[test]
fn templates_list_prints_all_four_preset_names() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args(["templates", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for name in [
        "btc_standard",
        "eth_standard",
        "long_tail_default",
        "mm_friendly",
    ] {
        assert!(
            stdout.contains(name),
            "missing preset name in output: {name}"
        );
    }
    assert_eq!(stdout.lines().count(), 4, "expected exactly 4 lines");
}

#[test]
fn templates_list_json_emits_array() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args(["--json", "templates", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse JSON");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 4);
}

#[test]
fn templates_show_btc_standard_produces_expected_json() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args(["--json", "templates", "show", "btc_standard"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse JSON");
    assert_eq!(v["asset_name"], "BTC");
    assert_eq!(v["asset_symbol"], "BTC");
    assert_eq!(v["max_leverage"], 50);
    assert_eq!(v["taker_fee_bps"], 45);
    assert_eq!(v["maker_fee_bps"], -10);
    let sources = v["oracle_sources"].as_array().unwrap();
    assert_eq!(sources.len(), 10);
}

#[test]
fn templates_show_unknown_preset_fails() {
    Command::cargo_bin(BIN)
        .unwrap()
        .args(["templates", "show", "no_such_preset"])
        .assert()
        .failure();
}

#[test]
fn perp_dry_run_prints_eight_action_lines() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args([
            "perp",
            "btc_standard",
            "--name",
            "BTC-PERP-2026",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        8,
        "expected 8 action lines in dry-run, got:\n{stdout}"
    );
    // Sanity check the order of action types in the lines.
    let expected = [
        "perp_register_asset",
        "perp_set_oracle",
        "perp_set_leverage",
        "perp_set_fees",
        "perp_set_min_order_size",
        "perp_set_funding_params",
        "perp_register_market",
        "perp_activate_market",
    ];
    for (i, exp) in expected.iter().enumerate() {
        assert!(
            lines[i].contains(exp),
            "line {i} expected to contain `{exp}`, got: {}",
            lines[i]
        );
    }
}

#[test]
fn perp_dry_run_propagates_name_override() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args([
            "perp",
            "eth_standard",
            "--name",
            "ETH-PERP-VANITY",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("ETH-PERP-VANITY"),
        "expected name override in dry-run output:\n{stdout}"
    );
}

#[test]
fn perp_dry_run_with_leverage_override_applies() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args([
            "perp",
            "btc_standard",
            "--name",
            "BTC-CUSTOM",
            "--leverage",
            "25",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // Find the perp_set_leverage line and check it has max_leverage: 25.
    let lev_line = stdout
        .lines()
        .find(|l| l.contains("perp_set_leverage"))
        .unwrap();
    assert!(
        lev_line.contains("\"max_leverage\":25"),
        "expected leverage=25 override: {lev_line}"
    );
}

#[test]
fn perp_dry_run_rejects_invalid_leverage() {
    Command::cargo_bin(BIN)
        .unwrap()
        .args([
            "perp",
            "btc_standard",
            "--name",
            "BTC",
            "--leverage",
            "200", // > 50
            "--dry-run",
        ])
        .assert()
        .failure();
}

#[test]
fn spot_dry_run_prints_four_action_lines() {
    let out = Command::cargo_bin(BIN)
        .unwrap()
        .args([
            "spot",
            "--base-asset",
            "2",
            "--quote-asset",
            "0",
            "--name",
            "ETH/USDC",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 4, "expected 4 lines; got:\n{stdout}");
}

#[test]
fn unknown_subcommand_fails_gracefully() {
    Command::cargo_bin(BIN)
        .unwrap()
        .args(["frobnicate"])
        .assert()
        .failure();
}
