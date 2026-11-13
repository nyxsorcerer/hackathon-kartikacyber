{% include "rules" %}

## Task

Analysis found that a commit of this Application's Own repository introduced a weakness. Draft the smallest fix for it as a patch. The Operator reviews the patch and approves it before Asset Monitor opens a draft pull request with exactly that patch.

inputs/source is a read-only checkout of the Own repository at base_ref (its default-branch head, or the analysed commit when the head is unknown), without git history. commit.json is the change that introduced the weakness, with its diff. analysis-report.md, when present, is the Analysis report behind the Verdict. prior-analyses.json, when present, is untrusted prior analysis: verify its claims against the source before relying on them.

Write the fix to /workspace/outputs/patch.diff as a git unified diff with a/ and b/ paths from the repository root, named exactly as the files are under inputs/source. Application code checks it with git apply against that checkout and rejects it if it does not apply, so copy context lines exactly. Change or add regular files only: no renames, symlinks or submodules, and never anything under .git/. Change .github/workflows only when the fix is there, and then set workflows to true. Leave unrelated code, formatting and dependencies as they are.

Build and run nothing: no shell, Docker daemon or package registry is reachable here. Return a summary of what the patch changes and why it removes the weakness, without quoting credentials.
