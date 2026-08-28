//! The workspace crate graph, read from `cargo metadata`.
//!
//! # Why `cargo metadata` rather than reading the TOML
//!
//! CD-I5 demands "a real graph check, not a substring grep". A hand-rolled TOML
//! reader would miss `[dependencies.foo]` table form, `[target.'cfg(...)'.dependencies]`,
//! renamed dependencies (`foo = { package = "bar" }`), and inherited workspace
//! dependencies — every one of which is a way to declare an edge the check would
//! then not see. `cargo metadata --no-deps` resolves all of that and is what
//! Cargo itself believes.
//!
//! `--no-deps` is deliberate: it reports each workspace member's *declared*
//! dependencies without resolving the registry graph, which is exactly what
//! CD-I2 asks about and is enough for CD-I5, because a path to
//! `twinvpn-cp-client` can only run through workspace members.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// One workspace member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The crate name.
    pub name: String,
    /// Its manifest path, for a violation's location.
    pub manifest_path: String,
    /// Its source directory, relative to the workspace root.
    pub dir: String,
    /// Every dependency it declares, in every section and every target,
    /// **including dev- and build-dependencies**. CD-I2 asks "what cryptography
    /// does this crate name", and a cipher pulled in by a test is still a name a
    /// reviewer must be able to find, so that check reads this list.
    pub dependencies: Vec<String>,
    /// Every dependency it declares **except dev-dependencies**.
    ///
    /// CD-I5 asks a different question from CD-I2 — not "what does this crate
    /// name" but "is there a path between the planes" — and a dev-dependency is
    /// not a path between the planes in any shipped artifact. It exists only
    /// while a test binary is being built.
    ///
    /// Reading the undifferentiated list for CD-I5 had a cost that was paid:
    /// `ownership.md` §10.8 **M-5**. CD-5 calls the mock adapter "the payoff" —
    /// *"with every shell deleted and a mock adapter bound, the core must still
    /// make every decision correctly"* — and the test that demonstrates it must
    /// drive the real machine, which means a **dev**-dependency on
    /// `twinvpn-core`. Counting that as a plane path made CB-2's own
    /// falsification test unwritable by the crates that most need to write it,
    /// so the rule was forbidding the evidence for the architecture it exists to
    /// protect.
    pub non_dev_dependencies: Vec<String>,
}

/// The workspace.
#[derive(Debug, Clone, Default)]
pub struct Workspace {
    /// Every member.
    pub packages: Vec<Package>,
    /// The workspace root directory.
    pub root: String,
}

impl Workspace {
    /// Reads the workspace at `manifest_path` via `cargo metadata`.
    ///
    /// # Errors
    ///
    /// A string describing why `cargo metadata` could not be read or parsed.
    pub fn load(manifest_path: &Path) -> Result<Self, String> {
        let root = manifest_path
            .parent()
            .ok_or("manifest path has no parent")?
            .to_path_buf();

        // Offline first: the lint must run on a CI runner with no network, and
        // `--no-deps` needs none. The retry exists only for a first run on a
        // machine whose lockfile predates a manifest change.
        let output =
            run_metadata(manifest_path, true).or_else(|_| run_metadata(manifest_path, false))?;

        let doc: serde_json::Value = serde_json::from_str(&output)
            .map_err(|e| format!("cargo metadata is not JSON: {e}"))?;

        let mut packages = Vec::new();
        for p in doc["packages"]
            .as_array()
            .ok_or("cargo metadata has no packages array")?
        {
            let name = p["name"].as_str().ok_or("package has no name")?.to_owned();
            let manifest = p["manifest_path"]
                .as_str()
                .ok_or("package has no manifest_path")?;
            let dir = Path::new(manifest)
                .parent()
                .and_then(|d| d.strip_prefix(&root).ok())
                .map_or_else(String::new, |d| d.to_string_lossy().into_owned());
            let manifest_rel = Path::new(manifest).strip_prefix(&root).map_or_else(
                |_| manifest.to_owned(),
                |p| p.to_string_lossy().into_owned(),
            );

            // `cargo metadata` spells the kind as a JSON null for a normal
            // dependency and the strings "dev" / "build" otherwise. Both lists
            // are built in one pass so they cannot drift.
            let empty = Vec::new();
            let raw = p["dependencies"].as_array().unwrap_or(&empty);
            let mut dependencies = Vec::new();
            let mut non_dev_dependencies = Vec::new();
            for d in raw {
                let Some(dep_name) = d["name"].as_str() else {
                    continue;
                };
                dependencies.push(dep_name.to_owned());
                if d["kind"].as_str() != Some("dev") {
                    non_dev_dependencies.push(dep_name.to_owned());
                }
            }

            packages.push(Package {
                name,
                manifest_path: manifest_rel,
                dir,
                dependencies,
                non_dev_dependencies,
            });
        }
        packages.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(Self {
            packages,
            root: root.to_string_lossy().into_owned(),
        })
    }

    /// One member, by name.
    #[must_use]
    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Every workspace member `name` reaches, directly or transitively.
    ///
    /// The transitive closure is what makes CD-I5 a graph check. Cycles cannot
    /// occur in a Cargo graph, but the walk is written to terminate on a repeat
    /// anyway rather than trusting that.
    #[must_use]
    pub fn transitive_workspace_deps(&self, name: &str) -> BTreeSet<String> {
        let by_name: HashMap<&str, &Package> =
            self.packages.iter().map(|p| (p.name.as_str(), p)).collect();
        let mut seen = BTreeSet::new();
        let mut stack = vec![name.to_owned()];
        while let Some(current) = stack.pop() {
            let Some(package) = by_name.get(current.as_str()) else {
                continue;
            };
            for dep in &package.non_dev_dependencies {
                // Only intra-workspace edges: a path between the planes can only
                // run through workspace members. And only NON-DEV edges: a
                // dev-dependency is not a path between the planes in any shipped
                // artifact (see `Package::non_dev_dependencies`, M-5).
                if by_name.contains_key(dep.as_str()) && seen.insert(dep.clone()) {
                    stack.push(dep.clone());
                }
            }
        }
        seen
    }
}

fn run_metadata(manifest_path: &Path, offline: bool) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut cmd = std::process::Command::new(cargo);
    cmd.arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(manifest_path);
    if offline {
        cmd.arg("--offline");
    }
    let out = cmd
        .output()
        .map_err(|e| format!("could not run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("cargo metadata output is not UTF-8: {e}"))
}
