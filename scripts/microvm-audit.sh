# microvm-audit: one contained run of the pinned security-audit skill against
# one commit of a repository, and the evidence of how contained it was.
#
#   microvm-audit --target <repo> --out <dir> [--rev <rev>] [--prompt <text>]
#
# The settings that make the run contained come from the profile this command
# was built with, not from the command line or the environment: the launcher
# gets an empty environment with only those, the run's own values and a short
# list of host variables (who you are, where your runtime and data dirs are,
# the API key, an upstream proxy). Afterwards the launch record is checked
# against the profile, and evidence.json says whether the run was valid.
#
# `set -euo pipefail` comes from writeShellApplication; @…@ from the build.
#
# Exit status: 0 valid; 2 invalid (not as contained as the profile says, or
# the egress verdict is not clean, or no record); 3 incomplete (contained,
# but the agent failed or the wall clock ran out); 64 usage; 1 setup failed.

prog=microvm-audit
runner=@RUNNER@
profile='@PROFILE@'
skill='@SKILL@'

usage() {
  cat >&2 <<EOF
usage: $prog --target <repo> --out <dir> [--rev <rev>] [--prompt <text>] [--evidence <dir>]

  --target <repo>    the git repository to audit (TARGET)
  --out <dir>        where reports go, one per target, kept across runs (AUDIT_OUT);
                     each run writes <dir>/run-<N>/
  --rev <rev>        the commit to audit (REV, default HEAD); exported with
                     git archive, so only committed, tracked files are seen
  --prompt <text>    the request to the skill (PROMPT, default: a full audit)
  --evidence <dir>   where the host keeps the run's evidence, out of the VM's
                     reach (AUDIT_EVIDENCE, default
                     \${XDG_STATE_HOME:-~/.local/state}/microvm-audit/runs)

ANTHROPIC_API_KEY must be set: the agent's home is new each run, so there is
no OAuth sign-in to reuse, and the key stays on the host, with the proxy.
EOF
  exit 64
}
die() { echo "$prog: $*" >&2; exit 1; }

target="${TARGET:-}" out="${AUDIT_OUT:-}" rev="${REV:-HEAD}"
prompt="${PROMPT:-security audit this codebase}"
evidence_root="${AUDIT_EVIDENCE:-${XDG_STATE_HOME:-$HOME/.local/state}/microvm-audit/runs}"
while [ $# -gt 0 ]; do
  case "$1" in
    --target|--out|--rev|--prompt|--evidence)
      [ $# -ge 2 ] || usage
      case "$1" in
        --target) target="$2" ;; --out) out="$2" ;; --rev) rev="$2" ;;
        --prompt) prompt="$2" ;; --evidence) evidence_root="$2" ;;
      esac
      shift 2 ;;
    -h|--help) usage ;;
    *) echo "$prog: unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$target" ] && [ -n "$out" ] || usage
[ -n "${ANTHROPIC_API_KEY:-}" ] || die "ANTHROPIC_API_KEY is not set (see --help)"
[ -n "$prompt" ] || die "--prompt is empty"

# --- the target: one commit, as git has it ----------------------------------
top="$(git -C "$target" rev-parse --show-toplevel 2>/dev/null)" || die "$target is not a git repository"
commit="$(git -C "$top" rev-parse --verify --quiet "$rev^{commit}")" || die "$rev is not a commit in $top"
name="$(basename "$top")"

# --- where the run writes ----------------------------------------------------
# Everything is checked before anything is created.
out="$(realpath -m "$out")"
evidence_root="$(realpath -m "$evidence_root")"
case "$out/" in "$top"/*) die "--out $out is inside the target: its reports would sit in the tree they audit" ;; esac
case "$evidence_root/" in "$out"/*|"$top"/*) die "--evidence must be outside --out and the target: the guest writes the one, and the record must not be where it can" ;; esac
mkdir -p "$out"
[ "$(realpath -e "$out")" = "$out" ] || die "--out $out changed under us"
n=1
for d in "$out"/run-*; do
  [ -d "$d" ] || continue
  k="${d##*/run-}"
  [[ "$k" =~ ^[0-9]+$ ]] && [ "$k" -ge "$n" ] && n=$((k + 1))
done
run="run-$n"
mkdir "$out/$run"

umask 077
mkdir -p "$evidence_root"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ev="$evidence_root/$name-${commit:0:12}-$(date -u +%Y%m%dT%H%M%SZ)-$run"
mkdir "$ev"
record="$ev/launch-record.json"

stage="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/microvm-audit-stage.XXXXXX" 2>/dev/null)" \
  || { mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"; stage="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/microvm-audit-stage.XXXXXX")"; }
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
git -C "$top" archive --format=tar "$commit" | tar -x -C "$stage/$name"

# --- the launch ----------------------------------------------------------------
p() { jq -r ".$1" <<< "$profile"; }
printf -v q_name '%q' "$name"
printf -v q_prompt '%q' "$prompt"
envv=(
  "HOME=$HOME" "PATH=$PATH"
  WORK_DIR="$stage/$name" SHARE_AUDIT_OUT="$out" LAUNCH_RECORD="$record"
  WORKSPACE_MODE=ephemeral WORKSPACE_GUARD=1 AGENT_HOME_MODE=ephemeral
  EGRESS_POLICY=enforce EGRESS_BUILTIN=0 CRI_STORAGE_SIZE=0
  API_BUDGET_REQUESTS="$(p budgetRequests)" API_BUDGET_TOKENS="$(p budgetTokens)"
  VM_MEM="$(p mem)" VM_VCPU="$(p vcpu)" VM_STORE_SIZE="$(p storeSize)"
  VM_TIMEOUT="$(p timeoutSeconds)" VM_TIMEOUT_GRACE="$(p timeoutGraceSeconds)"
  NO_PAUSE=1
  AGENTS_ARGS="--run $run --target $q_name --commit $commit --prompt $q_prompt"
)
for v in USER LOGNAME TERM LANG NO_COLOR XDG_RUNTIME_DIR XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME XDG_CONFIG_HOME \
         DBUS_SESSION_BUS_ADDRESS ANTHROPIC_API_KEY HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy; do
  [ -n "${!v:-}" ] && envv+=("$v=${!v}")
done

echo "$prog: $name at ${commit:0:12} → $out/$run (evidence: $ev)"
rc=0
( cd "$stage" && exec env -i "${envv[@]}" "$runner" ) </dev/null 2>&1 | tee "$ev/session.log" || rc="${PIPESTATUS[0]}"
ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- the evidence ----------------------------------------------------------------
# Every check compares the record — what the launcher says it ran with —
# with what this profile asks for.
if [ -s "$record" ] && jq -e . "$record" >/dev/null 2>&1; then
  rec="$(cat "$record")"
else
  rec=null
fi
jq -n --argjson r "$rec" --argjson p "$profile" --argjson skill "$skill" \
  --arg run "$run" --arg name "$name" --arg path "$top" --arg commit "$commit" --arg out "$out" \
  --arg prompt "$prompt" --arg started "$started" --arg ended "$ended" --argjson launcherExit "$rc" '
  def check($name; $ok; $got): {name: $name, ok: ($ok == true), got: $got};
  (if $r == null then [check("launch record written"; false; null)] else [
    check("launch record completed"; $r.ended != null; $r.ended),
    check("egress enforce"; $r.egress.policy == "enforce"; $r.egress.policy),
    check("no built-in allowlists"; $r.egress.builtinAllowlists == false; $r.egress.builtinAllowlists),
    check("model endpoint: Anthropic only"; ($r.egress.endpoints | map(.prefix)) == ["/anthropic"]; ($r.egress.endpoints | map(.prefix))),
    check("API budget as profiled"; $r.egress.apiBudget == {maxRequests: $p.budgetRequests, maxTokens: $p.budgetTokens}; $r.egress.apiBudget),
    check("workspace ephemeral and guarded"; $r.workspace.mode == "ephemeral" and $r.workspace.guard == true; $r.workspace),
    check("agent home ephemeral"; $r.agentHome.mode == "ephemeral"; $r.agentHome.mode),
    check("only the audit-out share, writable"; ($r.shares | map({name, guest, host, readOnly})) == [{name: "audit-out", guest: "/audit-out", host: $out, readOnly: false}]; $r.shares),
    check("environment: the API key only"; $r.env == {apiKeys: ["ANTHROPIC_API_KEY"], extraEnv: [], devShellFromHost: false}; $r.env),
    check("resources as profiled"; $r.resources == {memMiB: $p.mem, vcpus: $p.vcpu}; $r.resources),
    check("wall clock as profiled"; $r.timeout == {seconds: $p.timeoutSeconds, graceSeconds: $p.timeoutGraceSeconds}; $r.timeout),
    check("egress verdict clean"; $r.ended.egressVerdict.outcome == "clean"; $r.ended.egressVerdict)
  ] end) as $checks
  | ($checks | map(select(.ok | not) | .name)) as $failed
  | {version: 1, run: $run,
     status: (if $failed != [] then "invalid"
              elif $r.ended.timedOut or $r.ended.exitStatus != 0 then "incomplete"
              else "valid" end),
     failed: $failed,
     target: {name: $name, path: $path, commit: $commit},
     skill: $skill, profile: $p, prompt: $prompt,
     output: ($out + "/" + $run), started: $started, ended: $ended, launcherExit: $launcherExit,
     exitStatus: $r.ended.exitStatus, timedOut: $r.ended.timedOut,
     egressVerdict: $r.ended.egressVerdict, apiUsage: $r.ended.apiUsage,
     checks: $checks,
     files: {launchRecord: "launch-record.json", sessionLog: "session.log"}}' > "$ev/evidence.json"

# A copy beside the report, now that the VM is gone; the host copy is the one
# the guest never had a chance to touch.
mkdir -p "$out/$run/evidence"
cp "$ev"/* "$out/$run/evidence/"

status="$(jq -r .status "$ev/evidence.json")"
echo "$prog: $status — $out/$run (evidence: $ev/evidence.json)"
jq -r '.failed[] | "  failed: " + .' "$ev/evidence.json" >&2
case "$status" in
  valid) exit 0 ;;
  incomplete) exit 3 ;;
  *) exit 2 ;;
esac
