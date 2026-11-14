"""Exposure (A05): whether an Upstream commit reaches an Application's Locked version. A commit is
contained in a release tag when the tag reaches it, or reaches a commit with the same patch-id on a
watched branch (a backport); for SVN, when the tag was copied from a revision at or after it. Tag
reachability decides, never semantic-version order. Pure helpers over `run`, git in a read-only
mirror (Sources.github_mirror), or over a plugin's SVN tags (Sources.svn_tags); no database."""

import re

FIX = "Vulnerability fix"
# ponytail: backports are looked for among the newest 1000 non-merge commits of the Release
# branches that the default branch does not reach (and of the default branch too for a commit it
# does not reach), each git call bounded by sources.MIRROR_SECONDS; an older backport, or a scan
# that times out, is missed and its release reads as exposed. Keep patch-ids per repository if that
# matters.
EQUIVALENT_SCAN = 1000


def tag_forms(version, package):
    """The tag names a Locked version may have, in matching order."""
    return [f"v{version}", version, *([f"{package}@{version}"] if package else [])]


def tag_version(name, package):
    """The version the tag `name` stands for, or None when it is no release of `package`."""
    if package and name.startswith(package + "@"):
        return name[len(package) + 1:] or None
    match = None if "@" in name else re.fullmatch(r"v?(\d[\w.+-]*)", name)
    return match.group(1) if match else None


def tags(run, *args):
    """The names of the tags for-each-ref lists with `args`."""
    return run("for-each-ref", "--format=%(refname:strip=2)", *args, "refs/tags/").decode().split()


def locked_tag(run, version, package):
    """The first existing tag among tag_forms, or None."""
    found = set(tags(run))
    return next((form for form in tag_forms(version, package) if form in found), None)


def watched(repository):
    """The watched branches as refs: the default branch (or the repository's source_ref) and each
    Release branch."""
    head = f"refs/heads/{repository.source_ref}" if repository.source_ref else "HEAD"
    return [head, *(f"refs/heads/{name}" for name in repository.watched_branches or {})]


def patch_ids(run, log):
    """{patch-id: [commit]} of `git log -p` output."""
    found = {}
    for line in run("patch-id", "--stable", stdin=log).decode().splitlines():
        patch, commit = line.split()
        found.setdefault(patch, []).append(commit)
    return found


def equivalents(run, sha, refs):
    """The commits on the watched branches `refs` (the default branch first) that sha does not
    reach and that carry its patch (the same `git patch-id --stable`): its backports. For a commit
    on the default branch only the Release branches' own commits can be one, so only they are read."""
    own = list(patch_ids(run, run("log", "-1", "-p", "--no-color", sha)))
    if not own:  # a merge or an empty commit has no patch to match
        return []
    head, *branches = refs
    scan = refs
    if contains(run, head, [sha]):
        if not branches:
            return []
        scan = [*branches, "^" + head]
    log = run("log", "-p", "--no-merges", "--no-color", "--ignore-missing", f"--max-count={EQUIVALENT_SCAN}",
              *scan, "^" + sha)
    return [commit for commit in patch_ids(run, log).get(own[0], []) if commit != sha]


def contains(run, ref, shas):
    """Whether `ref` reaches any of `shas`: nothing reachable from one of them is missing from it."""
    return any(not run("rev-list", "--max-count=1", sha, "^" + ref).strip() for sha in shas)


def decide(verdict, locked_version, tag, contained, released=True):
    """(state, reason) of a Verdict at a Locked version whose tag is `tag` (None: none matches),
    which `contained` says reaches the commit; `released` says whether any release does. A
    Vulnerability introduced or Malicious change is exposed where the tag contains it; a
    Vulnerability fix where it does not, and everywhere while no release contains it. Unknown
    counts as exposed."""
    if verdict == FIX and not released:
        return "exposed", "no release contains the fix yet"
    if not locked_version:
        return "unknown", "No Locked version"
    if not tag:
        return "unknown", f"No release tag matches the Locked version {locked_version}"
    if verdict == FIX:
        return ("not_exposed", f"{tag} contains the fix") if contained else ("exposed", f"{tag} does not contain the fix")
    return ("exposed", f"{tag} contains the commit") if contained else ("not_exposed", f"{tag} does not contain the commit")


def releases(run, shas):
    """The tags that contain any of `shas`, newest first by creatordate."""
    return tags(run, "--sort=-creatordate", *(f"--contains={sha}" for sha in shas))


def release(names, package):
    """{tag, version} of the first of `names` that is a release of `package`, or None."""
    for name in names:
        version = tag_version(name, package)
        if version:
            return {"tag": name, "version": version}
    return None


def latest_without(run, shas, package):
    """The newest release (by creatordate) that contains none of `shas`: the safe version to pin."""
    return release(tags(run, "--sort=-creatordate", *(f"--no-contains={sha}" for sha in shas)), package)


def first_with(run, shas, package):
    """The oldest release (by creatordate) that contains any of `shas`: the first fixed release."""
    return release(tags(run, "--sort=creatordate", *(f"--contains={sha}" for sha in shas)), package)


def containing(run, shas, refs, limit=100):
    """(commits, truncated): each of `shas` (the commit, then its backports) followed by the commits
    on the watched branches `refs` that descend from it, oldest first, at most `limit`."""
    found = []
    for sha in shas:
        found += [sha, *run("rev-list", "--reverse", "--ancestry-path", "--ignore-missing", *refs, "^" + sha).decode().split()]
    found = list(dict.fromkeys(found))
    return found[:limit], len(found) > limit


def svn_releases(copied, revision):
    """The SVN tags (copied: {tag: revision}) copied at or after `revision`, newest first."""
    return sorted((name for name, rev in copied.items() if rev >= int(revision)), key=lambda name: -copied[name])


def svn_target(copied, revision, fix, package):
    """As first_with for a fix, else latest_without, ordered by the revision each tag was copied from."""
    if fix:
        return release(sorted((n for n, rev in copied.items() if rev >= int(revision)), key=copied.get), package)
    older = (n for n, rev in copied.items() if rev < int(revision))
    return release(sorted(older, key=copied.get, reverse=True), package)
