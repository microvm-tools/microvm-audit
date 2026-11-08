# microvm-audit

One command runs a pinned security-audit skill against one commit of a
repository, in a sealed [claude-microvm](https://github.com/nix-gizmos/agent-vm)
VM. It hands back the report and the evidence of how contained the run was.

```sh
export ANTHROPIC_API_KEY=…
make audit.run TARGET=~/work/domain-backend AUDIT_OUT=~/audits/domain-backend
# or: nix run .#default -- --target ~/work/domain-backend --out ~/audits/domain-backend
```

The skill is Cloudflare's
[security-audit-skill](https://github.com/cloudflare/security-audit-skill),
pinned in `flake.nix`. It executes target code (builds, tests, fuzzers) only
inside a sandbox with networking off, a sanitized environment, resource limits
and writes confined to scratch paths. Without one, every finding that needs
execution stays unproven. This repo provides that sandbox, and the VM around it.

## A run

`microvm-audit --target <repo> --out <dir> [--rev <rev>] [--prompt <text>] [--evidence <dir>]`

1. **The target is one commit.** `git archive` exports the commit (`--rev`,
   default `HEAD`) to a temporary directory: tracked files only, without
   history. Uncommitted changes, untracked files and `.git` stay behind.
2. **Each run gets a new directory,** `<out>/run-<N>`. Earlier runs of the
   same target sit beside it; the skill reads their `coverage-ledger.json` and
   `findings.json` and adds to them.
3. **The VM boots with the profile's settings and nothing else.** The launcher
   gets an empty environment. It holds the profile below, the run's own values,
   and a short list of host variables: who you are, your XDG directories,
   `DBUS_SESSION_BUS_ADDRESS`, `ANTHROPIC_API_KEY`, and an upstream
   `HTTPS_PROXY` / `NO_PROXY` for the host-side proxy. `EXTRA_ENV`,
   `EGRESS_ALLOW`, `DIRENV_ALLOW`, other agents' keys and the rest of your
   environment never reach it.
4. **The agent runs the skill** (`claude -p "/security-audit …"`) against
   `/work`, the exported commit. It writes the report to `/audit-out/run-<N>`.
   When it ends, its session transcripts are copied to `run-<N>/transcript/`
   and the VM powers off.
5. **The evidence is checked.** The launch record is compared with the profile
   and `evidence.json` is written. Both, with the launcher's output, go to the
   evidence directory on the host: by default
   `${XDG_STATE_HOME:-~/.local/state}/microvm-audit/runs/<target>-<commit>-<time>-run-<N>/`.
   A copy goes to `run-<N>/evidence/`.

`ANTHROPIC_API_KEY` is required. The agent's home is new every run, so there
is no OAuth sign-in to reuse. The key stays on the host, with the egress
proxy; the guest only ever sees a placeholder.

### The profile

Fixed at build time (`lib.defaultProfile` in `flake.nix`). Nothing on the
command line or in the environment changes it. A different profile is a
different build: `lib.mkAudit { system; profile = …; }`.

| | |
|---|---|
| Egress | `EGRESS_POLICY=enforce`, `EGRESS_BUILTIN=0`, no `EGRESS_ALLOW`: only the model API, through the host-side proxy that holds the key |
| API budget | 5000 requests and 30 M tokens per run; past them the proxy refuses (403) |
| Workspace | `WORKSPACE_MODE=ephemeral` (the guest's writes stay in the VM), `WORKSPACE_GUARD=1` |
| Agent home | `AGENT_HOME_MODE=ephemeral`: new for the run, removed after it |
| Shares | `/audit-out` (writable, the run's `--out`) is the only one besides `/work` and the agent home |
| Resources | 12 GiB memory, 6 vCPUs, a 20 GiB store disk, no container runtime |
| Wall clock | 3 h, then the VM's power button, `quit` 2 min later |
| Sandboxed target processes | at most 10 min, 2 GiB, 256 tasks, 2 CPUs, 256 MiB per file (`audit-sandbox`) |

### Evidence and exit status

`evidence.json` names:

- the target (path, commit) and the skill (repo, rev, `narHash`, the tree hash
  Nix checked);
- the profile and the request;
- the egress verdict and API usage from the launch record;
- every check it made, with what the record showed.

| status | exit | when |
|---|---|---|
| `valid` | 0 | the record shows everything the profile asks for, and the egress verdict is clean: every decision was an allowed model-API request |
| `incomplete` | 3 | all of the above, but the agent failed or the wall clock ran out |
| `invalid` | 2 | the record is missing, unfinished or shows less than the profile asks for, or the egress verdict is not clean |

The run is refused before anything starts, with exit 1 or 64, if any of these
holds:

- the target is not a repository;
- the rev is not a commit;
- `--out` lies inside the target;
- the evidence directory lies inside `--out` or the target;
- there is no API key.

## Inside the VM

**The skill** is copied into Claude Code's managed skills directory,
`/etc/claude-code/.claude/skills/security-audit/`. The copies are root's,
read-only, and take precedence over any skill of the same name. The skill is
pinned to a commit. `flake.lock` holds its tree hash, which Nix verifies when
it fetches. The agent can't fetch it itself: there is no network to fetch from.

**The target's Claude configuration is data, not configuration.** A repository
can carry `.claude/settings.json`, `.mcp.json`, `.claude/skills/` and
`CLAUDE.md`. Its hooks, MCP servers, `apiKeyHelper` and `env` would run as the
agent: outside the sandbox, next to the model API. So:

- **No project settings:** the agent runs `claude --setting-sources user` and
  reads none. Managed settings alone are not enough here: the target's
  `apiKeyHelper` still ran under them, as checked against claude-code 2.1.317.
- **Managed settings** (`/etc/claude-code/managed-settings.json`):
  - skills, agents, hooks and MCP servers only from managed sources
    (`strictPluginOnlyCustomization`, `allowManagedHooksOnly`,
    `allowManagedMcpServersOnly`);
  - the target's `CLAUDE.md` files are not loaded as instructions
    (`claudeMdExcludes`);
  - `WebSearch` and `WebFetch` are denied. Web search runs on the model
    provider's side, past the egress proxy and out of its audit log.

**Target code runs in `audit-sandbox`**, never directly. The agent is told so,
and the skill requires it:

```sh
audit-sandbox --scratch /audit-out/run-3/agents/h1/scratch -- go test ./...
audit-sandbox --describe        # the controls and limits, as JSON, for the records
```

| control | how |
|---|---|
| no network | a network namespace of its own: loopback only, so the target cannot reach the model proxy and spend the run's budget |
| empty environment | `--clearenv`, then a fixed allowlist: the toolchain's `PATH`; `HOME`, `TMPDIR` and caches in scratch; offline Go, npm, pip and cargo; plus `--env NAME=VALUE`. Names that look like credentials or proxies are refused |
| read-only target and toolchain | `/work` (or `--source`), `/nix` and `/etc` mounted read-only. The agent's home, `/run`, `/tmp` and the rest of `/audit-out` are absent |
| writes only to scratch | `--scratch` must be an existing directory named `scratch` below `/audit-out`, given as a canonical path (no symlinks) |
| limits | a cgroup scope: memory with no swap, tasks, CPU. An rlimit on file size, no core dumps, a wall clock (exit 124). No nested user namespaces, no capabilities |

`audit-sandbox` refuses, with exit 125, rather than run with less. That covers
the cgroup controllers it needs not being delegated, a limit above the
profile's, or a misplaced scratch directory. The VM is the outer boundary;
the sandbox is the one inside it that keeps target code away from the agent's
home, the retained output and the model API.

**The toolchain**, the same for the agent and the sandbox:

- bash, coreutils, git, make, gcc, pkg-config, Go, Node.js and Python;
- offline: `GOPROXY=off`, `GOTOOLCHAIN=local`, and `-mod=vendor` in the
  sandbox.

`lib.mkAudit { toolchain = pkgs: [ … ]; }` sets another.

## Checks

```sh
make check        # nix flake check
```

CI runs the same on every pull request and on `main`, and builds the whole
runner (`.github/workflows/ci.yml`). Renovate proposes input updates; a new
skill rev comes as its own PR, to be read before it is merged.

| check | what |
|---|---|
| `sandbox` | `audit-sandbox` in a NixOS VM test, each control checked from inside the sandbox. Every denial has a positive control first, so a sandbox that failed to start cannot pass as one that denied |
| `wrapper` | `microvm-audit` with a stand-in launcher that writes its record from the environment it got: what reaches the launcher, the export, run numbering, and each status |
| `guest` | the guest's evaluated configuration: the share, the skill's files and modes, the managed settings, the agent's flags |

The managed settings and `--setting-sources user` were checked once against
the guest's claude-code (2.1.317), with a hostile target and a stand-in API
that captured the first request:

- **What loaded:** the pinned skill loaded, and the `Agent` tool was offered.
- **What did not:** the target's skill, `CLAUDE.md`, hooks, MCP server and
  `apiKeyHelper` neither loaded nor ran, and `WebSearch`/`WebFetch` were not
  offered.
- **An invalid managed value** doesn't stop Claude Code. It's reported and
  treated as the strict setting.

None of this is a `nix flake check` yet, because it needs the unfree binary
and a writable `/etc`.

## Not yet

- **A real run.** Nothing here has booted the audit VM against a live API.
  Launching needs the host; the first run against domain-backend is the test
  of the whole.
- **Scratch disk use is not capped.** Each sandboxed process is limited per
  file, but `/audit-out` is a host directory, so the total is not limited.
- **Offline builds beyond vendored Go.** Only the toolchain in the guest
  exists. A target needing more, such as a Nix dev shell or `node_modules`, has
  to have it pre-realized or vendored. That is not built yet.
- **The transcripts are the agent's own account.** They are written in the
  guest. The launch record and the egress audit log are the host's.
