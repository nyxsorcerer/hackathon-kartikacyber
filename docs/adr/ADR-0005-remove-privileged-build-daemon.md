# ADR-0005: Build Labs through the broker on the host Engine, and remove the privileged build daemon

## Status

Accepted, 2026-11-12. Extends the risk statement in ADR-0002.

## Context and decision point

ADR-0002 accepted a runner broker that holds the Docker socket. In Numen, Lab builds already go through that broker on the host Engine: `build_lab` in `runner/numen_runner/engine.py` refuses privileged flags and mounts, and each run gets its own bridge network.

Numen also starts a privileged Docker-in-Docker daemon, with unbounded storage, for the agent runs that build code: for `cve_analysis` since commit `d724279`, and for `commit_analysis` since `4970c7b`, the fork base. ADR-0004 makes all Analysis read-only, so that daemon no longer has any user. Labs still build images from code that attackers can influence, on the same machine that stores the Provider accounts.

## Decision

Remove the privileged build daemon and its image. Keep building Labs through the broker on the host Engine, in the two phases of ADR-0004, with these limits:

- each Lab image at most 4 GB;
- builds limited to 15 minutes, runs to 10 minutes;
- every Lab's images and containers removed after its run;
- Lab networks with no route to the application network.

Run every demo and hackathon deployment on a disposable VM that holds only demo-scoped, spend-capped keys.

The accepted risk is that escaping a Lab build or run container reaches the host Engine, which means owning the VM.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| Keep the privileged daemon and move Lab builds into it | Separate daemon storage | Escaping a build lands in a privileged container, which is no stronger than the host Engine |
| Rootless Docker, Sysbox or gVisor for Labs | Stronger isolation for untrusted builds | New runtime to install and verify |
| A remote build service | Untrusted builds leave the host | Breaks the all-Docker, self-hosted requirement |
| Static Proofs only, no Labs | No untrusted builds | Loses the reproduced n-day Proof the demo depends on |
| Host Engine through the broker, daemon removed, disposable host (chosen) | Reuses Numen's tested Lab path; one privileged component fewer | Escaping a container still means owning the VM |

## Reconsider when

Multiple Operators or other untrusted people come into scope, or a hardened container runtime has been verified with Numen's runner.
