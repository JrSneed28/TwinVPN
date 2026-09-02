//! What this CLI does when whatever was reading it stops.
//!
//! `lab-t1` reads this binary through pipes — `list … | head -1 | awk`, and
//! `capabilities | tee` — and `head` closes the pipe as soon as it has the line
//! it wanted. Rust ignores `SIGPIPE`, so the next `println!` unwraps an `EPIPE`
//! and panics, and the step failed with 101 on a command that had already
//! printed what its consumer asked for (job 100262708050).
//!
//! The consumer going away is not an error here, and this test is what keeps it
//! from becoming one again.

use std::process::{Command, Stdio};

/// Runs a subcommand with nothing on the other end of its stdout.
fn exit_code_with_no_reader(args: &[&str]) -> Option<i32> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_twinlab-scenarios"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary under test is built by `cargo test`");
    // Closing the read end is the whole experiment: every write the child makes
    // from here on fails the way it failed under `head -1`.
    drop(child.stdout.take());
    child.wait().expect("the child is ours to reap").code()
}

#[test]
fn a_reader_that_walks_away_does_not_panic_the_command() {
    for args in [&["list"][..], &["matrix"][..]] {
        assert_eq!(
            exit_code_with_no_reader(args),
            Some(0),
            "`{}` did its job and then died of its consumer leaving; an exit \
             code has to keep meaning what §3.1 says it means, and 101 from a \
             panic is not one of the three answers",
            args.join(" ")
        );
    }
}
