# ADR-0008: Add a PHP Lab stack beside the Node stack

## Status

Accepted, 2026-11-15. Amends A07: its "In the first release, the only Lab stack is Node", and its phase-one `composer --no-scripts`. ADR-0004's two phases and ADR-0005's limits apply unchanged. Implemented by B09 in `docs/prd/asset-monitor-r2-prd.md`.

## Context and decision point

PHP Applications, WordPress.org plugins and Packagist Upstream repositories get Verdicts today but no Lab Proof. `build_lab` refuses a bundle without `vulnerable-app/package.json` (`lab_stack_unsupported`). The backend repeats that refusal in `artifacts.completeness` and `workflows.lab_run`.

Composer differs from npm in ways that matter for a Lab:

- `--no-scripts` stops only the root package's scripts. A dependency of type `composer-plugin` runs its own PHP during install unless `--no-plugins` is set too.
- A project's `composer.json` can turn plugins back on. There is nothing like the Node base's global `ignore-scripts=true`.
- Dist archives come from code hosts, such as GitHub's API and codeload, not from repo.packagist.org. A failed dist falls back to cloning with git.
- Packagist publishes no integrity hash for GitHub dists, and those archives are not byte-stable. The commit SHA in `composer.lock` is the only pin.
- PHP runs any file it is given. If Composer is anywhere in the build image, a `RUN` can reach it however it is spelled, and a `RUN` that loads `vendor/autoload.php` runs every dependency's autoload files.

A Lab also runs exactly one container with no sidecars, so an app that needs a database server cannot start in it.

## Decision

1. **A second Lab stack, in two images.**
   - `asset-monitor-lab-php:0.1.0` is built from a digest-pinned PHP 8.4 CLI image on Debian bookworm. It carries the image label and the uid 10001 user, with `/opt/lab` owned by that user. It has no Composer and no git.
   - `asset-monitor-lab-php-fetch:0.1.0` is that image plus Composer, pinned by version and SHA-256, and unzip. It is used only for phase one, and has no git either, so Composer can never fall back to cloning sources.
   - The PoC still runs in `asset-monitor-lab:0.1.0`, under Python.
2. **The base image names the stack.** The `FROM` line of the bundle's Dockerfile decides:
   - `asset-monitor-lab:0.1.0` is Node, and needs `vulnerable-app/package.json`;
   - `asset-monitor-lab-php:0.1.0` is PHP, and needs `vulnerable-app/composer.json`;
   - a Dockerfile that names both, or names the fetch image, is refused with `lab_stack_unsupported`.
3. **Phase one: fetch, with nothing run.** It runs in the fetch image with no model credential:
   - the command is `composer install --no-scripts --no-plugins --no-interaction --prefer-dist --no-progress`, with the audit off;
   - Composer's home and cache live on the run's volume;
   - egress goes through the run's gateway to a fixed list of Composer hosts: by default `repo.packagist.org`, `api.github.com` and `codeload.github.com`;
   - only `vendor/` comes back, with its generated autoloader, and it may hold regular files, directories and symbolic links only.
4. **Phase two: build and run with no network.**
   - The build runs with `--network none`, from the base that has no Composer.
   - A PHP-stack Dockerfile may not contain `RUN` at all, and is refused before Approval with a message that says so. A PHP app needs no build step, and extensions cannot be installed offline anyway. The build therefore uses `vendor/` exactly as fetched, and runs no PHP.
   - The app runs under PHP's built-in web server, `php -S 0.0.0.0:8080`, on the internal Lab network, at the usual `TARGET_URL`.
5. **The same limits.** ADR-0005's image size, deadlines, cleanup and network rules apply unchanged.
6. **No database servers in this release.** A bundle is refused before Approval, with a message that says so, if its vulnerable app:
   - is WordPress core (`wp-settings.php`), or
   - requires a MySQL or PostgreSQL extension in `composer.json`.

   This holds for an Own-head Proof too: application code reads the Own repository's `composer.json` and file list from its stored snapshot. Apps that use SQLite run.
7. **Upstream Proofs for Packagist packages** follow A07's vulnerable-app rules: the Own repository's head with the Locked version installed, or a minimal app that pins it.
   - Application code takes the Locked version from the watched Upstream repository's tree at the commit `composer.lock` names, or at the Locked version's tag for a minimal app.
   - It copies that tree under `vulnerable-app/.asset-monitor/<vendor>/<name>/`, so the Lab never downloads the package it is proving.
   - For an Own-head Proof it rewrites only that package's entry in `composer.lock`: `"dist": {"type": "path", "url": ".asset-monitor/<vendor>/<name>", "reference": "<commit>"}`, `"transport-options": {"symlink": false, "relative": true}`, and no `source`. `composer.json` is left alone, so the lock's content hash still matches.
   - For a minimal app it writes a `composer.json` with a path repository for that folder (`"options": {"symlink": false, "versions": {"<vendor>/<name>": "<Locked version>"}}`) and requires exactly the Locked version.
   - A package whose source is not a watched GitHub repository is refused with `package_untrusted`.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| Copy PHP into the Node base | One Lab base | PHP's shared libraries and extensions would be copied by hand into another image; fragile |
| Debian's `php-cli` package | No new base image | The version moves with apt and cannot be pinned by digest |
| Compose Labs with a database sidecar | WordPress Proofs | A new multi-container network design; deferred |
| Use Packagist dists as fetched | No vendoring code | No byte-stable integrity, so the Proof could run a different version |
| One PHP base with Composer off the `PATH` and `RUN` lines that name Composer refused | One image | A `RUN` can still reach the phar, or load the autoloader, so dependency code could run in the build |
| A digest-pinned PHP base without Composer, a separate fetch image with scripts and plugins off, no `RUN`, and a vendored Locked version (chosen) | Reuses the Lab path, and nothing from a dependency runs, by construction | Two images to build, phase-one egress reaches GitHub's code hosts, and WordPress Proofs wait |

## Consequences

- AC-A07's "A Lab build cannot run a dependency install script" now also holds for Composer plugins, root scripts and autoload files, because the build image has no Composer and the Dockerfile has no `RUN`.
- **Egress.** PHP phase one reaches general code hosting, which anyone can publish to. It carries no credential, so GitHub's rate limit for unauthenticated requests can fail a fetch, which shows as `lab_dependencies_failed`.
- **Tests.** The test and demo overlays set the Composer host list to `registry.invalid` and vendor everything, so no test reaches a third party.
- **What changes together.** The prompt's bundle section, the `LAB_BASES` mirrors in the runner and backend tests, and the Node-only tests all change in the same phase.
- **WordPress.org plugin Proofs stay unavailable.** They need WordPress core, and an SVN source is refused with `package_untrusted`.
- The Composer details above, the lock form included, come from upstream Composer, not from this repository. A runtime test installs the vendored form offline with the pinned Composer version.

## Reconsider when

WordPress, or other apps that need a database server, need Lab Proofs.
