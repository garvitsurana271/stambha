//! The fork's hand-written options against the startup lines a stick
//! holds: each in every place on each line, twice, and with bad values, so
//! no option of the fork's changes what a line setup wrote means.
use super::*;
use crate::laptop::{self, Choice, Facts};
use alloc::{format, string::String, vec, vec::Vec};

/// The plain `macOS` startup choice of a tester's stick, as setup wrote it
/// (its ECID and network made up), one option and its value a group.
const MACOS: [&str; 9] = [
    "--storage @disk",
    "--nor @disk",
    "--preboot @disk",
    "--ecid 0x0000000000001234",
    "--guest-network",
    "--wifi HomeNet",
    "--wifi-country IN",
    "--input",
    "--guest-pes 8",
];

/// The stick's startup choices: `macOS`, then the ones hand-written from it.
fn stick_lines() -> Vec<Vec<String>> {
    let base: Vec<String> = MACOS.iter().map(|group| String::from(*group)).collect();
    let with = |extra: &[&str]| {
        let mut line = base.clone();
        line.extend(extra.iter().map(|group| String::from(*group)));
        line
    };
    vec![
        base.clone(),
        with(&["--laptop off"]),
        with(&["--profile", "--laptop off"]),
        with(&["--bluetooth-lend", "--laptop off"]),
        with(&["--acpi-hardware"]),
    ]
}

/// The lines setup itself writes (its Preboot, bundle and Install lines),
/// which must parse and serialize exactly as they are.
fn setup_lines() -> Vec<Vec<String>> {
    let groups = |groups: &[&str]| groups.iter().map(|g| String::from(*g)).collect::<Vec<_>>();
    let storage = format!("--storage {DISK}");
    let nor = format!("--nor {DISK}");
    let preboot = format!("--preboot {DISK}");
    vec![
        groups(&[
            &storage,
            &nor,
            &preboot,
            "--ecid 0x0000000000001234",
            "--external-disks",
            "--guest-network",
        ]),
        groups(&[&storage, &nor, "--bundle \\EFI\\stela\\r"]),
        groups(&[
            &storage,
            &nor,
            "--bundle \\stela\\boot\\22A\\r",
            "--ecid 0x0000000000000001",
            "--install \\stela\\install\\22A\\payload.json",
            "--install-source 33333333-4444-5555-6666-777777777777",
            "--development-restore",
        ]),
    ]
}

/// `--system` and `groups`, with `inserted` before group `at`.
fn line(groups: &[String], inserted: &[(&str, usize)]) -> String {
    let mut text = String::from("--system");
    for at in 0..=groups.len() {
        for (option, _) in inserted.iter().filter(|(_, place)| *place == at) {
            text.push(' ');
            text.push_str(option);
        }
        if let Some(group) = groups.get(at) {
            text.push(' ');
            text.push_str(group);
        }
    }
    text
}

/// One of the fork's hand-written options: its spellings, what each sets,
/// and the errors a bad value and a second copy give.
struct Fork {
    valid: &'static [&'static str],
    set: fn(&mut System, &str),
    bad: &'static [(&'static str, Error)],
    /// `None` for a flag a second copy of which is accepted, as `--profile`.
    duplicate: Option<Error>,
}

fn value(option: &str) -> &str {
    option.split_once(' ').map_or("", |(_, value)| value)
}

fn on(option: &str) -> bool {
    value(option) == "on"
}

fn forks() -> [Fork; 13] {
    [
        Fork {
            valid: &["--acpi-hardware"],
            set: |o, _| o.acpi_hardware = true,
            bad: &[],
            duplicate: None,
        },
        Fork {
            valid: &[
                "--asus-mode performance",
                "--asus-mode turbo",
                "--asus-mode silent",
                "--asus-mode off",
            ],
            set: |o, t| o.asus_mode = Some(AsusMode::parse(value(t)).unwrap()),
            bad: &[
                ("--asus-mode", Error::AsusMode),
                ("--asus-mode balanced", Error::AsusMode),
                ("--asus-mode Performance", Error::AsusMode),
            ],
            duplicate: Some(Error::DuplicateAsusMode),
        },
        Fork {
            valid: &["--keep-running-on-panic"],
            set: |o, _| o.keep_running_on_panic = true,
            bad: &[],
            duplicate: None,
        },
        Fork {
            valid: &["--tlbi-keep on", "--tlbi-keep off"],
            set: |o, t| o.tlbi_keep = Some(on(t)),
            bad: &[
                ("--tlbi-keep", Error::TlbiKeep),
                ("--tlbi-keep yes", Error::TlbiKeep),
                ("--tlbi-keep ON", Error::TlbiKeep),
                ("--tlbi-keep 1", Error::TlbiKeep),
            ],
            duplicate: Some(Error::DuplicateTlbiKeep),
        },
        Fork {
            valid: &["--tlbi-verify-check"],
            set: |o, _| o.tlbi_verify_check = true,
            bad: &[],
            duplicate: Some(Error::DuplicateTlbiVerifyCheck),
        },
        Fork {
            valid: &["--host-core on", "--host-core off"],
            set: |o, t| o.host_core = Some(on(t)),
            bad: &[
                ("--host-core", Error::HostCore),
                ("--host-core true", Error::HostCore),
                ("--host-core 1", Error::HostCore),
            ],
            duplicate: Some(Error::DuplicateHostCore),
        },
        Fork {
            valid: &["--gpu-aspm off", "--gpu-aspm firmware"],
            set: |o, t| o.gpu_aspm = Some(GpuAspm::parse(value(t)).unwrap()),
            bad: &[
                ("--gpu-aspm", Error::GpuAspm),
                ("--gpu-aspm on", Error::GpuAspm),
                ("--gpu-aspm performance", Error::GpuAspm),
            ],
            duplicate: Some(Error::DuplicateGpuAspm),
        },
        Fork {
            valid: &["--hle"],
            set: |o, _| o.hle = true,
            bad: &[],
            duplicate: Some(Error::DuplicateHle),
        },
        Fork {
            valid: &["--hle-off bzero", "--hle-off memmove,strlen"],
            set: |o, t| {
                o.hle_off = match value(t) {
                    "bzero" => vec![stela_engine::hle::Id::Bzero],
                    _ => vec![
                        stela_engine::hle::Id::Memmove,
                        stela_engine::hle::Id::Strlen,
                    ],
                }
            },
            bad: &[
                ("--hle-off", Error::HleId),
                ("--hle-off nosuch", Error::HleId),
                ("--hle-off memmove,", Error::HleId),
            ],
            duplicate: Some(Error::DuplicateHle),
        },
        Fork {
            valid: &["--tier2 on", "--tier2 off"],
            set: |o, t| o.tier2 = Some(on(t)),
            bad: &[
                ("--tier2", Error::Tier2),
                ("--tier2 yes", Error::Tier2),
                ("--tier2 ON", Error::Tier2),
            ],
            duplicate: Some(Error::DuplicateTier2),
        },
        Fork {
            valid: &["--tier2-check"],
            set: |o, _| o.tier2_check = true,
            bad: &[],
            duplicate: None,
        },
        Fork {
            valid: &["--pack-preload on", "--pack-preload off"],
            set: |o, t| o.pack_preload = Some(on(t)),
            bad: &[
                ("--pack-preload", Error::PackPreload),
                ("--pack-preload yes", Error::PackPreload),
                ("--pack-preload OFF", Error::PackPreload),
            ],
            duplicate: Some(Error::DuplicatePackPreload),
        },
        Fork {
            valid: &["--store-esp"],
            set: |o, _| o.store_esp = true,
            bad: &[],
            duplicate: None,
        },
    ]
}

/// `--core-trial` is a read-only boot of its own: on any line that names
/// a disk or a network it is refused, wherever it stands, so a stray copy
/// never boots a stick's macOS without its disks.
#[test]
fn core_trial_anywhere_on_a_stick_or_setup_line_is_refused() {
    for groups in all_lines() {
        for at in 0..=groups.len() {
            let text = line(&groups, &[("--core-trial", at)]);
            assert_eq!(
                System::parse(&text),
                Err(Error::Constraint(Constraint::CoreTrial)),
                "{text}"
            );
        }
    }
    let trial = "--system --bundle \\stela\\boot\\m2u\\r --storage-ram 0x200000000 --native-cores 16 --core-trial";
    assert!(round_trip(trial).core_trial);
}

fn all_lines() -> Vec<Vec<String>> {
    let mut lines = stick_lines();
    lines.extend(setup_lines());
    lines
}

#[test]
fn setup_lines_and_the_stick_s_choices_mean_what_they_meant() {
    for groups in setup_lines() {
        let text = line(&groups, &[]);
        assert_eq!(round_trip(&text).to_string(), text);
    }
    for groups in stick_lines() {
        let options = round_trip(&line(&groups, &[]));
        // None of the fork's options is set by a line that does not hold it.
        let held = |option: &str| groups.iter().any(|g| g.starts_with(option));
        assert_eq!(options.acpi_hardware, held("--acpi-hardware"));
        assert_eq!(options.asus_mode, None);
        assert!(!options.keep_running_on_panic);
        assert_eq!(options.tlbi_keep(), (false, false));
        assert!(!options.host_core());
        assert_eq!(options.gpu_aspm, None);
        assert!(!options.hle && options.hle_off.is_empty());
        assert!(!options.core_trial);
        assert!(options.tier2.is_none() && !options.tier2_check && !options.tier2_runs());
        assert!(options.pack_preload.is_none() && !options.pack_preload());
        assert!(!options.store_esp);
    }
}

#[test]
fn each_fork_option_means_the_same_in_every_place_of_every_line() {
    let mut checked = 0;
    for groups in all_lines() {
        let plain = System::parse(&line(&groups, &[])).unwrap();
        for fork in forks() {
            for option in fork.valid {
                let mut expected = plain.clone();
                (fork.set)(&mut expected, option);
                for at in 0..=groups.len() {
                    let text = line(&groups, &[(option, at)]);
                    assert_eq!(round_trip(&text), expected, "{text}");
                    checked += 1;
                }
            }
        }
    }
    // 8 lines of 3 to 11 groups, 19 spellings.
    assert!(checked > 1000, "{checked}");
}

#[test]
fn a_second_copy_anywhere_is_refused_or_changes_nothing() {
    for groups in all_lines() {
        let plain = System::parse(&line(&groups, &[])).unwrap();
        for fork in forks() {
            let first = fork.valid[0];
            let second = fork.valid[fork.valid.len() - 1];
            for i in 0..=groups.len() {
                for j in i..=groups.len() {
                    let text = line(&groups, &[(first, i), (second, j)]);
                    match &fork.duplicate {
                        Some(error) => {
                            assert_eq!(System::parse(&text), Err(*error), "{text}")
                        }
                        None => {
                            let mut expected = plain.clone();
                            (fork.set)(&mut expected, first);
                            assert_eq!(System::parse(&text), Ok(expected), "{text}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_bad_value_anywhere_is_its_option_s_own_error() {
    for groups in all_lines() {
        for fork in forks() {
            for (bad, error) in fork.bad {
                for at in 0..=groups.len() {
                    let text = line(&groups, &[(bad, at)]);
                    assert_eq!(System::parse(&text), Err(*error), "{text}");
                }
            }
        }
    }
}

/// A laptop's facts as the FA608 reads them.
const LAPTOP: Facts = Facts {
    pm_profile: Some(2),
    battery: true,
    lid: true,
    precision_touchpad: true,
    trackpad_port: true,
};

#[test]
fn laptop_off_takes_nothing_and_leaves_acpi_hardware_on() {
    let base = line(&stick_lines()[0], &[]);
    let mut off = System::parse(&format!("{base} --laptop off --acpi-hardware")).unwrap();
    let plan = laptop::plan(&off, LAPTOP);
    for choice in [plan.battery, plan.lid, plan.brightness_keys, plan.trackpad] {
        assert_eq!(choice, Choice::Skipped("--laptop off"));
    }
    plan.apply(&mut off);
    assert!(off.acpi_hardware);
    assert_eq!((off.battery, off.lid, off.trackpad), (None, None, None));
    assert!(!off.brightness_keys);
    // The battery + lid choice: auto, so the laptop takes its features too.
    let mut auto = System::parse(&format!("{base} --acpi-hardware")).unwrap();
    let plan = laptop::plan(&auto, LAPTOP);
    plan.apply(&mut auto);
    assert!(auto.acpi_hardware && auto.brightness_keys);
    assert_eq!(auto.battery, Some(Battery::Host));
    assert_eq!(auto.lid, Some(Lid::Method));
    assert_eq!(auto.trackpad, Some(GuestTrackpad::Mt2));
    assert!(plan.takes_brightness_keys());
}

#[test]
fn profile_takes_the_host_core_and_the_tlbi_keep_beside_it() {
    let base = line(&stick_lines()[0], &[]);
    let speed = "--profile --tlbi-keep on --tlbi-verify-check --host-core on";
    let options = round_trip(&format!("{base} {speed}"));
    assert!(options.profile && options.parallel && options.host_core());
    assert_eq!(options.tlbi_keep(), (true, true));
    // Eight PEs and a host core on a 16-thread laptop.
    assert_eq!(
        crate::host_core::plan(options.host_core(), options.parallel, 8, 16),
        crate::host_core::Plan::Reserve { executors: 9 }
    );
    // The profile entry as the stick has it (`--laptop off`) with them.
    let profiled = round_trip(&format!("{base} --profile --laptop off {speed}"));
    assert_eq!(profiled.laptop(), Laptop::Off);
    assert_eq!(profiled.tlbi_keep(), (true, true));
}
