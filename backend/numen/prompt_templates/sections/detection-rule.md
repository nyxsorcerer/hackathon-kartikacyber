## Detection rule

For a Malicious change, write detection-rule.yar: one YARA Detection rule that matches what the change added and matches nothing in the parent, the state just before the change, nor, for a change made after the Baseline, anything in the Baseline. Match the payload itself, such as its loader, its host or a string only it contains, never text the parent already had.

Application code validates the rule with yara in a job with no network: it must match at least one file the commit changed, must match no file in the parent tree and, after the Baseline, no file in the Baseline tree. A rule that fails any check leaves the static Proof a Draft. A rule that uses include or the console module is refused, and the rule stays under 64 KiB.

In `indicators`, list what the change added. `files` copies each added or changed path exactly as commit.json lists them; `hosts`, `urls` and `commands` copy each string exactly as the diff's added lines show them. Application code keeps only indicators it finds there and computes the files' hashes itself, so never decode, guess or rewrite a value. Use empty lists for kinds the change does not have.

In `reachable_secrets`, name each secret the payload could reach and that the Operator must rotate, such as the npm publish token in the CI environment, and never their values. Application code adds the commits and releases that contained the change and the Detection rule to run on the server, so the cleanup report needs nothing else from you. report.md explains what the payload does and how you know.

Never execute, install, import or render the payload, not even to deobfuscate it: read it only as text.
