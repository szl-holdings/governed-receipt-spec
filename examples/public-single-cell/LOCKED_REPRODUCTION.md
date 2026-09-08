# Locked reproduction: dependencies, container and offline execution

This adds a reproducible software environment to the existing descriptive GEO example. It does not change the analysis, original observed output, author attribution or unsigned trust model.

## What is pinned

`requirements-linux-cp312.lock` specifies all five runtime packages and one exact wheel SHA-256 for each. `reproduction-profile.json` records filenames, sizes, versions and the public metadata observations used to review them. The wheels were downloaded and matched against the PyPI release metadata; a fresh environment installed them from local files with hash enforcement and passed pip's dependency check.

The Dockerfile pins the official Python 3.12.14 slim image by its **linux/amd64 platform manifest digest**, not merely its tag. The registry manifest bytes were hashed and matched to the recorded digest. The two observation jobs linked from the profile qualify these inputs, not a later source build or a biological conclusion.

This is deliberately one supported platform: CPython 3.12.14, Linux x86_64, glibc >= 2.34. It is not an untested cross-platform lock. A compatible Docker host is the recommended path on another operating system. Package hashes are not signatures, and a fixed base image still requires reviewed security updates.

## Checkout the version you intend to test

Use a fresh clone and an exact published commit containing this document. Record it before running. The exact PR/post-merge workflow logs identify the source they qualified; do not substitute a newer moving branch and claim it is the same subject.

The older historical example can be reproduced from published ancestor `66700778fd995051f01c9ed7fe42226b464a31a4`. Its analysis file is identical, but it predates the new lock and Dockerfile. The original CPU-run source identifier remains in the historical receipt; it is not rewritten to the later published commit.

## Native locked execution (reviewed Linux platform)

In a new Python 3.12.14 virtual environment, from the repository root:

```sh
python examples/public-single-cell/check_reproduction.py --environment
python -m pip --isolated download --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r examples/public-single-cell/requirements-linux-cp312.lock --dest /tmp/cell-wheels-new
python examples/public-single-cell/check_reproduction.py --wheelhouse /tmp/cell-wheels-new
python -m pip --isolated install --no-index --find-links /tmp/cell-wheels-new --only-binary=:all: --require-hashes -r examples/public-single-cell/requirements-linux-cp312.lock
python -m pip check
python examples/public-single-cell/check_reproduction.py --environment --installed
python examples/public-single-cell/run_example.py --output /tmp/cell-host-new
```

Download needs network access. The installation uses the local verified files. It does not build source distributions or silently fetch unlisted dependencies. Choose new paths rather than replacing a prior run.

## Digest-pinned container and network-disabled calculation

The following shell commands are for a Linux Docker host. Docker Desktop users should adapt host mount paths explicitly. The earlier native command has downloaded and hash-verified the source file. The container reuses only that file, read-only; it cannot fetch a different input.

```sh
docker build --platform linux/amd64 --build-arg "SOURCE_REVISION=$(git rev-parse HEAD)" --iidfile /tmp/cell-image-new.id -f examples/public-single-cell/Dockerfile -t cell-repro:review .
mkdir /tmp/cell-container-new
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,size=16m -v /tmp/cell-host-new/source.tsv.gz:/input/source.tsv.gz:ro -v /tmp/cell-container-new:/out:rw cell-repro:review --input /input/source.tsv.gz --output /out/result
cmp /tmp/cell-host-new/summary.json /tmp/cell-container-new/result/summary.json
cmp /tmp/cell-host-new/receipt.json /tmp/cell-container-new/result/receipt.json
```

The Docker **build** downloads the pinned base and hash-checked package artifacts. Only the **calculation container** runs without networking. The base digest and the locally built final image ID are distinct and are both retained by CI. Identical output files do not assert byte-identical container rebuilds, trusted timestamps, signed results or externally independent replication.

## Qualification and maintenance

The existing public-example workflow performs the full download, actual pip tamper rejection, source/record regressions, real-data host calculation, container build, network-disabled calculation and cross-environment output comparisons. All steps must pass at the exact candidate before normal merge. No new scheduler, publisher, secret or artifact-upload action is introduced.

A dependency or base-image update is a reviewed source change: resolve upstream metadata again, update the profile and lock together, rerun the checks, and retain the new source and image identities. Do not silently substitute a mirror, broaden the hashes, ignore a missing wheel, or report an unexecuted target as supported.

Primary references: [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/) and [Docker image pinning](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions).
