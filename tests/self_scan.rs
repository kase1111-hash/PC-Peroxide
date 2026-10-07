//! The built-in rules must not flag PC-Peroxide's own executables, wherever a
//! copy of them sits on disk.

use pc_peroxide::detection::YaraEngine;

fn assert_not_flagged(binary_path: &str) {
    let engine = YaraEngine::with_default_rules().unwrap();
    let binary = std::fs::read(binary_path).unwrap();
    // Several rules only apply to PE files; give non-Windows builds an MZ
    // header so those rules are evaluated too.
    let mut data = b"MZ".to_vec();
    data.extend_from_slice(&binary);

    let hits: Vec<String> = engine
        .scan_data(&data)
        .into_iter()
        .map(|m| {
            let mut ids: Vec<_> = m
                .matches
                .iter()
                .filter(|(_, offsets)| !offsets.is_empty())
                .map(|(id, _)| id.clone())
                .collect();
            ids.sort();
            format!("{} {:?}", m.rule_name, ids)
        })
        .collect();
    assert!(hits.is_empty(), "{} matched: {:?}", binary_path, hits);
}

#[test]
fn builtin_rules_do_not_match_cli_binary() {
    assert_not_flagged(env!("CARGO_BIN_EXE_pc-peroxide"));
}

#[cfg(feature = "gui")]
#[test]
fn builtin_rules_do_not_match_gui_binary() {
    assert_not_flagged(env!("CARGO_BIN_EXE_pc-peroxide-gui"));
}
