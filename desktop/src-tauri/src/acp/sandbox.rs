//! The OS sandbox every agent adapter runs under. Enforcement used to live
//! in policy.rs as a shell-command parser deciding which permission requests
//! to auto-allow, and it lost by construction: bash's lexer is the spec, any
//! approximation misses shapes, and every miss was a dialog. Now the adapter
//! process (and so every command the agent runs) is spawned under an OS
//! sandbox: read anything, network allowed, write only where the app says.
//! Dialogs are gone because the kernel is the guard; a forbidden write fails
//! in the agent's own transcript instead of interrupting the user.
//!
//! The mechanism differs by platform. macOS wraps every spawn in
//! `sandbox-exec` with a Seatbelt profile. Linux wraps it in bubblewrap
//! (`bwrap`): `/` mounted read-only, writable roots re-mounted writable,
//! `/tmp` a private tmpfs. Under Flatpak there is no nested wrapper at all:
//! the Flatpak sandbox itself is the guard, so the invocation passes through.
//! Where neither wrapper exists (a bare Linux box without bubblewrap), the
//! adapter runs unwrapped rather than failing — same behavior as macOS with
//! sandbox-exec missing, and worth saying out loud instead of hiding.
//!
//! No entry in any profile is user-managed. Every writable root is computed
//! at spawn time from facts the app already owns: the project the user
//! opened, the app's own data directory (or the dev checkout), the per-user
//! temp tree, and the state directories of the agents the app ships. If a
//! future change wants a user-typed path or a setting here, it is the wrong
//! change.

use std::path::{Path, PathBuf};

/// Wrap an adapter invocation in its platform sandbox. The wrapper execs the
/// target in place, so the child pid, process group, and kill semantics the
/// caller relies on are unchanged.
#[cfg(target_os = "macos")]
pub(super) fn wrap(
    program: String,
    args: Vec<String>,
    project: &Path,
    engine_root: &Path,
) -> (String, Vec<String>) {
    let mut wrapped = vec!["-p".into(), profile(project, engine_root), program];
    wrapped.extend(args);
    ("/usr/bin/sandbox-exec".into(), wrapped)
}

#[cfg(not(target_os = "macos"))]
pub(super) fn wrap(
    program: String,
    args: Vec<String>,
    project: &Path,
    engine_root: &Path,
) -> (String, Vec<String>) {
    // Flatpak already confines this process tree; nesting bubblewrap inside
    // it needs user namespaces Flatpak does not grant, and adds nothing the
    // outer sandbox does not enforce.
    if std::env::var_os("FLATPAK_ID").is_some() {
        return (program, args);
    }
    match bubblewrap() {
        Some(bwrap) => {
            let mut wrapped = bwrap_args(project, engine_root);
            wrapped.push(program);
            wrapped.extend(args);
            (bwrap.to_string_lossy().into_owned(), wrapped)
        }
        None => {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "nurb: bubblewrap not found; agent processes run without a filesystem \
                     sandbox. Install bubblewrap to restore the write boundary."
                )
            });
            (program, args)
        }
    }
}

/// The bubblewrap executable, if this system has one at a conventional path.
#[cfg(not(target_os = "macos"))]
fn bubblewrap() -> Option<PathBuf> {
    ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

/// Bubblewrap arguments equivalent to the Seatbelt profile below: everything
/// readable, nothing writable, then the app-derived roots re-mounted
/// writable. Later mounts win, so the binds override the read-only `/`.
#[cfg(not(target_os = "macos"))]
fn bwrap_args(project: &Path, engine_root: &Path) -> Vec<String> {
    let mut args = vec![
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        // Devices and proc stay live: the adapters drive terminals, and the
        // nurb engine probes memory through /proc.
        "--dev-bind".to_string(),
        "/dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "/proc".to_string(),
        // A private tmpfs: scratch space like macOS grants /private/tmp.
        "--tmpfs".to_string(),
        "/tmp".to_string(),
    ];
    for root in writable_roots(project, engine_root) {
        if root.is_dir() {
            let text = root.display().to_string();
            args.push("--bind".into());
            args.push(text.clone());
            args.push(text);
        }
    }
    // The Wayland/PulseAudio socket directory holds lock files clients
    // rewrite, and the adapters may play sounds or open portals.
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let text = runtime.display().to_string();
        args.push("--bind".into());
        args.push(text.clone());
        args.push(text);
    }
    args
}

/// The Seatbelt profile. Later rules win, so: allow everything, deny all
/// writes, then re-allow the app-derived writable roots.
#[cfg(target_os = "macos")]
fn profile(project: &Path, engine_root: &Path) -> String {
    let mut rules = String::new();
    for root in writable_roots(project, engine_root) {
        rules.push_str(&format!("  (subpath {})\n", quoted(&root)));
    }
    if let Some(home) = home() {
        // The agents' own state (`~/.claude` and the `~/.claude.json` family,
        // `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.grok`): one prefix rule per agent
        // home, so session files, config, and their temp-file variants are
        // all covered without enumerating filenames.
        for dot in [".claude", ".codex", ".gemini", ".cursor", ".grok"] {
            rules.push_str(&format!(
                "  (regex #\"^{}/\\{dot}\")\n",
                regex_escaped(&home.display().to_string())
            ));
        }
    }
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny file-write*)\n\
         (allow file-write*\n\
         \x20 (literal \"/dev/null\")\n\
         \x20 (literal \"/dev/tty\")\n\
         \x20 (literal \"/dev/dtracehelper\")\n\
         \x20 (regex #\"^/dev/ttys[0-9]\")\n\
         \x20 (subpath \"/private/tmp\")\n\
         {rules})\n"
    )
}

/// Directory roots the adapter may write, resolved because the wrappers match
/// syscall paths after resolution (/tmp is really /private/tmp on macOS).
/// Roots that do not exist are skipped: a rule for a missing path is dead
/// weight, and everything here is created by the OS or the app before an
/// adapter ever spawns.
fn writable_roots(project: &Path, engine_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |path: PathBuf| {
        if let Ok(real) = path.canonicalize() {
            if !roots.contains(&real) {
                roots.push(real);
            }
        }
    };
    // The project the user opened, and the engine's home: the provisioned
    // app-data dir on user machines, the repo checkout in dev builds (where
    // `uv run --project` and `npx -y` write build state).
    push(project.to_path_buf());
    push(engine_root.to_path_buf());
    // The per-user temp tree and its sibling cache tree; child shells inherit
    // the same answers.
    let temp = std::env::temp_dir();
    push(temp);
    if let Some(home) = home() {
        // Tool caches (uv resolves to ~/Library/Caches on macOS and ~/.cache
        // everywhere, npm to ~/.npm) and nurb's own config.
        push(home.join("Library/Caches"));
        push(home.join(".cache"));
        push(home.join(".npm"));
        push(home.join(".config/nurb"));
        for dot in [".claude", ".codex", ".gemini", ".cursor", ".grok"] {
            push(home.join(dot));
        }
    }
    roots
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// A Seatbelt string literal: double-quoted, with quotes and backslashes
/// escaped ("Banana Holder" is a normal project name; quotes would be
/// pathological but must not break out of the string).
#[cfg(target_os = "macos")]
fn quoted(path: &Path) -> String {
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// A path made safe for use inside a Seatbelt regex literal.
#[cfg(target_os = "macos")]
fn regex_escaped(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if "\\^$.|?*+()[]{}\"".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::process::Command;

    fn sh(profile: &str, script: &str) -> bool {
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", profile, "/bin/sh", "-c", script])
            .output()
            .expect("sandbox-exec runs")
            .status
            .success()
    }

    #[test]
    fn the_kernel_enforces_the_write_boundary() {
        // The test IS the security property: writes inside the project
        // succeed, writes beside it fail, reads work everywhere.
        let project = std::env::temp_dir().join(format!("nurb-sbx-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("nurb-sbx-out-{}", std::process::id()));
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        // A profile whose only writable root is the project: temp trees are
        // excluded here on purpose, because the test's "outside" lives there.
        let profile = format!(
            "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath {}) (literal \"/dev/null\"))\n",
            quoted(&project.canonicalize().unwrap())
        );
        assert!(sh(&profile, &format!("echo hi > '{}/inside.txt'", project.display())));
        assert!(!sh(&profile, &format!("echo hi > '{}/escape.txt'", outside.display())));
        assert!(sh(&profile, "cat /etc/hosts > /dev/null"));
        std::fs::remove_dir_all(&project).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn the_real_profile_admits_the_project_and_agent_state() {
        let project = std::env::temp_dir().join(format!("nurb-sbx-real-{}", std::process::id()));
        std::fs::create_dir_all(&project).unwrap();
        let profile = profile(&project, &project);
        // Inside the project: allowed. The user's own dotfiles: refused.
        assert!(sh(&profile, &format!("echo hi > '{}/part.py'", project.display())));
        assert!(!sh(&profile, "echo hacked >> \"$HOME/nurb-sbx-canary\" && rm \"$HOME/nurb-sbx-canary\""));
        // Agent state under each agent home writes fine (created and removed).
        for dot in [".claude", ".codex", ".gemini", ".cursor", ".grok"] {
            let existed = home().map(|h| h.join(dot).exists()).unwrap_or(false);
            assert!(sh(
                &profile,
                &format!("mkdir -p \"$HOME/{dot}/nurb-sbx-test\" && rmdir \"$HOME/{dot}/nurb-sbx-test\"")
            ));
            // Do not leave dotdirs behind for agents this machine lacks.
            if !existed {
                if let Some(h) = home() {
                    std::fs::remove_dir(h.join(dot)).ok();
                }
            }
        }
        std::fs::remove_dir_all(&project).ok();
    }

    #[test]
    fn quoting_survives_hostile_paths() {
        let path = PathBuf::from("/Users/me/Documents/nurb/Banana Holder");
        assert_eq!(quoted(&path), "\"/Users/me/Documents/nurb/Banana Holder\"");
        let tricky = PathBuf::from("/Users/me/a\"b");
        assert_eq!(quoted(&tricky), "\"/Users/me/a\\\"b\"");
        assert_eq!(regex_escaped("/Users/j.p"), "/Users/j\\.p");
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    /// Whether the machine can actually enforce anything here; without
    /// bubblewrap (or inside Flatpak) the wrapper passes through honestly.
    fn enforcing() -> bool {
        bubblewrap().is_some() && std::env::var_os("FLATPAK_ID").is_none()
    }

    fn sh(project: &Path, engine_root: &Path, script: &str) -> bool {
        let (program, args) = wrap(
            "/bin/sh".into(),
            vec!["-c".into(), script.to_string()],
            project,
            engine_root,
        );
        std::process::Command::new(program)
            .args(args)
            .output()
            .expect("the sandboxed shell runs")
            .status
            .success()
    }

    #[test]
    fn the_kernel_enforces_the_write_boundary() {
        if !enforcing() {
            return;
        }
        let project = std::env::temp_dir().join(format!("nurb-lsbx-{}", std::process::id()));
        // The escape probe must sit outside every granted root: temp trees
        // ARE granted (scratch space), so it lives directly under $HOME,
        // which no rule covers.
        let outside = match home() {
            Some(home) => home.join(format!("nurb-lsbx-out-{}", std::process::id())),
            None => return,
        };
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        assert!(sh(&project, &project, &format!("echo hi > '{}/inside.txt'", project.display())));
        assert!(!sh(&project, &project, &format!("echo hi > '{}/escape.txt'", outside.display())));
        assert!(sh(&project, &project, "cat /etc/hosts > /dev/null"));
        std::fs::remove_dir_all(&project).ok();
        std::fs::remove_dir_all(&outside).ok();
    }
}
