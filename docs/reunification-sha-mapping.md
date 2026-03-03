# Reunification SHA Mapping (master -> codex/reunify-modernize-2026-02-19)

This file tracks the Phase 1 selective replay from `master` onto the reunification branch created from `develop`.

| Old SHA (master) | New SHA (reunification branch) | Scope |
|---|---|---|
| `0e71dd7` | `3306c1ba6aa3cb71be63bdfa3d69d0551626642b` | `.gitignore` hardening (keys/certs) |
| `cebb016` | `82e16253de6537b0890b20baa24164132664138d` | `.gitignore` hardening (`*.pyc`) |
| `5ed85df` | `1a36854b548b841e766905098dc93c597dff88f9` | `.gitignore` hardening (auth/logs keepers) |
| `fbc7830` | `b3bf93ce75c464afa410e5fe64b663103892c21e` | webcam similarity logic (`unavailable_wallonia2`, `videojet`) |
| `4bad3b4` | `2bd32decd1430eda760d0eb968c4c5dda1cbae64` | webcam similarity assets (`unavailable_wallonia2.jpg` + updated wallonia sample) |

## Notes

- Conflict resolution policy: keep Python 3 compatibility from `develop` while replaying `master` deltas.
- For `.gitignore`, `__pycache__` from `develop` was kept in addition to replayed rules.
