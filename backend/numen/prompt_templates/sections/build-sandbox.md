## Build sandbox

A build run additionally gives you a shell, git and a private Docker daemon in a writable /workspace.

When /workspace/repo exists it is a full clone of source_url, with every branch, tag and its whole history, already checked out at the pinned revision: use it to read the real history and diffs (git log, show, blame, checkout of the parent) instead of cloning again, and fetch from origin only for history newer than the run. Clone source_url yourself only when it is absent.

Install the dependencies the pinned release declares, then docker build and docker run your bundle and exercise poc.py against it until it genuinely works. Record in report.md what you actually observed building and running.

Ship the bundle on a base you actually built against: asset-monitor-lab:0.1.0 is preloaded in the build daemon. Iterate the way the verifier works, or the bundle passes for you and fails for it: build the final bundle with DOCKER_BUILDKIT=0 so you use the same builder, run it with the verifier's own bounds (--cpus 2 --memory 6144m --pids-limit 4096), publish 8080, and point TARGET_URL at it to exercise poc.py end to end.

How the build sandbox works, so you do not have to discover it:

1. DOCKER_HOST=tcp://docker:2375 is a private daemon in its own container, not a local socket; a port a container publishes is reached at http://docker:<port>, never localhost.
2. The daemon sees only /workspace, at the same paths. /workspace/inputs is a separate read-only mount it cannot see: a container you bind mount it into gets an empty directory, so copy what a container needs out of inputs/ first.
3. Containers the daemon starts can write to a bind mount only under /workspace/share; everything else under /workspace belongs to your user and is read-only to them.
4. docker cp copies between a container and /workspace, never directly between two containers: copy out to /workspace/share, then in.
5. Your own shell reaches only GitHub, npm, Packagist/Composer, PyPI and Docker Hub through the run's proxy; builds and containers on the daemon have their own outbound access, so install system packages inside Dockerfiles.
6. Disk is limited: remove test containers and images you no longer need (docker rm, docker rmi, docker image prune -f) before building again.
7. Write scratch files anywhere under /workspace except inputs/; they are never published, only outputs/ is.
