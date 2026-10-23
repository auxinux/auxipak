# AuxiPak

*English · [Français](README.fr.md)*

**AuxiPak** is the cross-platform application distribution service of the
AuxiNux ecosystem: <https://auxipak.auxinux.ca>.

It searches, installs, upgrades and removes applications on Debian, Ubuntu,
AuxiNuxOS, VirtuaOS, Windows and macOS, from signed `.aupak` packages and
TUF-authenticated indexes.

## Philosophy

- **AuxiPak does not replace package managers.** It uses the native mechanisms
  allowed on each system: APT on Debian/Ubuntu, the `auxi` command on AuxiNuxOS
  (where APT is blocked), a configurable adapter on VirtuaOS, winget/MSI/EXE on
  Windows, pkg/dmg/Homebrew on macOS, and a `files` copy method.
- **AuxiPak never updates the operating system.**
- **Declarative and verifiable.** The `instruction.auxipak` manifest contains no
  free-form command; everything is validated before execution, without a shell;
  scripts require explicit permission.
- **Explicit trust.** TUF-protected indexes (authenticity, freshness, rollback
  protection), Ed25519-signed packages, archives inspected before extraction.
- **Human in the loop.** A submission (including from CI or an AI agent) is only
  published after approval by a human reviewer.

### AuxiNux statuses

Each application in the official repository carries a status, assigned by a
reviewer and **distinct from the signature** (which only attests origin and
integrity):

| Status | Meaning |
|---|---|
| **AuxiNux Verified** | assessed and compliant with the AuxiNux criteria |
| **AuxiNux Compatible** | acceptable, with documented caveats |
| **Not reviewed** | published, not yet assessed |

Until a human reviews it, an application may show an **automatic AI
pre-assessment**, always labelled “automatic AI analysis” with its sources.
Repositories added by the user are always shown as “external”: they cannot
claim an AuxiNux status.

### Languages

Everything is bilingual. **English by default**; French when the system (or the
browser) is in French, or when chosen explicitly (`auxipak set lang fr`,
`AUXIPAK_LANG`, the website language selector). Any other language: English.

## Components

| Component | Role |
|---|---|
| `auxipak` (`client/`) | command-line client: `search`, `install`, `remove`, `update`, `upgrade`, `list`, `info`, `verify`, `clean`, `repo`, `repair`, `doctor` |
| `auxipak-builder` (`builder/`) | package creation, validation, build, static tests, signing and submission; key ceremony |
| `auxipak-server` (`server/`) | REST API, bilingual web interface, review and publication, signing, index and TUF metadata generation |
| `auxipak-core` (`shared/`) | shared library: manifest, `.aupak` format, signatures, indexes, TUF |
| `web/` | templates, translations and theme of the web interface |
| `deploy/` | Docker, Compose, Nginx, systemd, operations scripts |
| `examples/auxipak-demo/` | demonstration application |

Everything is written in Rust: standalone binaries, one validation library
shared by the client, the builder and the server.

## Installing the client

```sh
curl -fsSL https://auxipak.auxinux.ca/install.sh | sh      # Linux, macOS
```

```powershell
irm https://auxipak.auxinux.ca/install.ps1 | iex           # Windows
```

Details and uninstallation: <https://auxipak.auxinux.ca/docs> and
[docs/INSTALLATION.md](docs/INSTALLATION.md) (French).

## Quick start (development)

Requirements: Rust ≥ 1.89, Docker (or a local PostgreSQL).

```console
$ git clone https://github.com/auxinux/auxipak.git && cd auxipak
$ cargo build                                   # auxipak, auxipak-builder, auxipak-server

# Development server (TEST keys generated automatically)
$ docker compose -f deploy/docker-compose.dev.yml up --build -d
$ docker compose -f deploy/docker-compose.dev.yml exec server auxipak-server create-admin --username admin
$ curl -fsS http://127.0.0.1:8080/api/v1/health

# Build the demonstration package
$ AUXIPAK_BUILDER=$PWD/target/debug/auxipak-builder examples/auxipak-demo/build.sh 1.0.0 dist/
$ target/debug/auxipak verify dist/AuxiPakDemo-1.0.0-mul.aupak

# Full end-to-end demonstration (ephemeral server and database)
$ PG_ADMIN_URL=postgres://postgres:password@127.0.0.1:5432/postgres tests/e2e/run-local.sh
```

Web interface: <http://127.0.0.1:8080> (administration: `/admin`).

## Documentation

The detailed technical documentation in `docs/` is written in French:
installation, command reference, builder, manifest specification, `.aupak`
format, API, deployment, signing and keys, architecture, contributing, roadmap,
translations, security and changelog. See [README.fr.md](README.fr.md) for the
index.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
