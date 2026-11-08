# audit-sandbox: run one target-controlled command (a build, a test, a fuzzer,
# a fixture) under the controls the security-audit skill requires before it
# executes target code, or refuse:
#
#   - no network but a private loopback: the target cannot reach the model
#     proxy, which spends the run's API budget with the host's key;
#   - an empty environment, filled from a fixed allowlist, with HOME, TMPDIR
#     and every cache inside the scratch directory;
#   - the target source and the toolchain read-only; the scratch directory,
#     a `scratch` below /audit-out, the only writable path;
#   - memory, task and CPU limits (a cgroup), a file-size limit, and a wall
#     clock, each at most the profile's.
#
# The VM is the outer boundary; this is the one inside it that keeps target
# code away from the agent's home, the retained output and the model API.
# `set -euo pipefail` comes from writeShellApplication; @…@ from the build.

prog=audit-sandbox
scratch_root=@SCRATCH_ROOT@
max_time=@TIME@ max_mem=@MEM@ max_tasks=@TASKS@ max_cpus=@CPUS@ max_fsize=@FSIZE@
toolpath=@TOOLPATH@

usage() {
  cat >&2 <<EOF
usage: $prog --scratch <dir> [options] -- <command> [args…]
       $prog --describe

  --scratch <dir>     the only writable directory: an existing directory named
                      'scratch' below $scratch_root (the skill's
                      <output-dir>/agents/<id>/scratch)
  --source <dir>      read-only target tree (default: /work)
  --cwd <dir>         working directory (default: the scratch directory)
  --env NAME=VALUE    add a variable to the empty environment (repeatable)
  --time <seconds>    wall clock (default and maximum: $max_time)
  --mem <MiB>         memory (default and maximum: $max_mem)
  --tasks <n>         processes and threads (default and maximum: $max_tasks)
  --cpus <n>          CPUs' worth of time (default and maximum: $max_cpus)
  --file-size <MiB>   largest file it may write (default and maximum: $max_fsize)
  --describe          print the controls and limits as JSON

Exit status: the command's; 124 when the wall clock ran out; 125 refused.
EOF
  exit 125
}
refuse() { echo "$prog: refused: $*" >&2; exit 125; }

describe() {
  cat <<EOF
{"sandbox": "audit-sandbox (bubblewrap in a cgroup scope, inside the audit VM)",
 "network": "none: a private network namespace with loopback only",
 "environment": "empty, then a fixed allowlist (PATH to the read-only toolchain; HOME, TMPDIR, caches inside scratch; offline settings for Go, npm, pip and cargo) and --env",
 "filesystem": {"readOnly": ["/nix", "/etc", "/bin", "/usr", "the --source tree (default /work)"],
                "writable": ["the --scratch directory, a 'scratch' below $scratch_root"],
                "absent": ["/home/agent", "/run", "/tmp", "the rest of $scratch_root"]},
 "namespaces": "user (no nested user namespaces), pid, ipc, uts, cgroup, mount, network",
 "capabilities": "none",
 "limits": {"wallClockSeconds": $max_time, "memoryMiB": $max_mem, "tasks": $max_tasks, "cpus": $max_cpus, "fileSizeMiB": $max_fsize, "swap": 0, "coreDumps": 0},
 "exitStatus": {"timedOut": 124, "refused": 125}}
EOF
  exit 0
}

uint() { [[ "$2" =~ ^[1-9][0-9]{0,8}$ ]] || refuse "$1 wants a positive integer, not '$2'"; }
cap() { uint "$1" "$2"; [ "$2" -le "$3" ] || refuse "$1 $2 is above the profile's maximum, $3"; }

scratch="" source=/work cwd="" time=$max_time mem=$max_mem tasks=$max_tasks cpus=$max_cpus fsize=$max_fsize
envs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --scratch|--source|--cwd|--env|--time|--mem|--tasks|--cpus|--file-size)
      [ $# -ge 2 ] || usage
      case "$1" in
        --scratch) scratch="$2" ;;
        --source) source="$2" ;;
        --cwd) cwd="$2" ;;
        --env) envs+=("$2") ;;
        --time) cap --time "$2" "$max_time"; time="$2" ;;
        --mem) cap --mem "$2" "$max_mem"; mem="$2" ;;
        --tasks) cap --tasks "$2" "$max_tasks"; tasks="$2" ;;
        --cpus) cap --cpus "$2" "$max_cpus"; cpus="$2" ;;
        --file-size) cap --file-size "$2" "$max_fsize"; fsize="$2" ;;
      esac
      shift 2 ;;
    --describe) describe ;;
    --) shift; break ;;
    -h|--help) usage ;;
    *) echo "$prog: unknown option: $1" >&2; usage ;;
  esac
done
[ $# -gt 0 ] || usage
[ -n "$scratch" ] || refuse "--scratch is required: target code writes nowhere else"

# Paths are taken only in their canonical form: no symlink, `.` or `..` in
# them, so what is checked is what gets mounted.
canonical() { # flag, path
  local real
  [[ "$2" == /* ]] || refuse "$1 wants an absolute path, not '$2'"
  real="$(realpath -e -- "$2" 2>/dev/null)" || refuse "$1 $2 does not exist"
  [ "$real" = "${2%/}" ] || refuse "$1 $2 is not canonical (it resolves to $real); pass that, without symlinks, . or .."
  [ -d "$real" ] || refuse "$1 $2 is not a directory"
}
canonical --scratch "$scratch"; scratch="${scratch%/}"
[[ "$scratch" == "$scratch_root"/* ]] && [ "$(basename "$scratch")" = scratch ] \
  || refuse "--scratch must be a directory named 'scratch' below $scratch_root, not $scratch"
[ -O "$scratch" ] && [ -w "$scratch" ] || refuse "--scratch $scratch is not yours to write"
canonical --source "$source"; source="${source%/}"
case "$source" in
  "$scratch"|"$scratch"/*) refuse "--source $source is inside the scratch directory, which is writable already: use --cwd" ;;
  "$scratch_root"|"$scratch_root"/*) refuse "--source must not be below $scratch_root: the retained output stays away from target code" ;;
  /|/home|/home/*|/run|/run/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*) refuse "--source $source exposes more than a source tree" ;;
esac
[[ "$scratch" == "$source"/* ]] && refuse "--scratch inside --source would make part of the target writable"
cwd="${cwd:-$scratch}"
canonical --cwd "$cwd"; cwd="${cwd%/}"

set_env=()
for e in "${envs[@]}"; do
  name="${e%%=*}"
  [[ "$e" == *=* ]] && [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || refuse "--env wants NAME=VALUE, not '$e'"
  shopt -s nocasematch
  if [[ "$name" =~ (KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PROXY) ]]; then
    shopt -u nocasematch; refuse "--env $name: credentials and proxies have no place in the sandbox (use dummy values under another name)"
  fi
  shopt -u nocasematch
  case "$name" in PATH|HOME|TMPDIR|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|BASH_ENV|ENV) refuse "--env $name is fixed by the sandbox" ;; esac
  set_env+=(--setenv "$name" "${e#*=}")
done

# The limits are a cgroup scope under the user's systemd. Without the memory,
# pids and cpu controllers delegated there it cannot hold them: refuse rather
# than run with less than it promises.
uid="$(id -u)"
controllers="/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers"
for c in memory pids cpu; do
  grep -qw "$c" "$controllers" 2>/dev/null \
    || refuse "the '$c' cgroup controller is not delegated to your systemd user manager ($controllers): the limits cannot be enforced"
done
[ -n "${XDG_RUNTIME_DIR:-}" ] || export XDG_RUNTIME_DIR="/run/user/$uid"

mkdir -p "$scratch"/{home,tmp,cache,config,data,go}

exec systemd-run --user --scope --quiet --collect \
  -p MemoryMax="${mem}M" -p MemorySwapMax=0 -p TasksMax="$tasks" -p CPUQuota="$((cpus * 100))%" \
  -- prlimit --fsize="$((fsize * 1024 * 1024))" --core=0 --nofile=4096 \
  -- timeout --kill-after=10 "$time" \
  bwrap --unshare-all --unshare-user --disable-userns --die-with-parent --new-session --cap-drop ALL \
    --hostname audit-sandbox --clearenv \
    --ro-bind /nix /nix --ro-bind /etc /etc --ro-bind-try /bin /bin --ro-bind-try /usr /usr \
    --proc /proc --dev /dev \
    --ro-bind "$source" "$source" --bind "$scratch" "$scratch" --chdir "$cwd" \
    --setenv PATH "$toolpath" --setenv LANG C.UTF-8 --setenv TERM dumb \
    --setenv HOME "$scratch/home" --setenv TMPDIR "$scratch/tmp" \
    --setenv XDG_CACHE_HOME "$scratch/cache" --setenv XDG_CONFIG_HOME "$scratch/config" --setenv XDG_DATA_HOME "$scratch/data" \
    --setenv GOPATH "$scratch/go" --setenv GOCACHE "$scratch/cache/go-build" --setenv GOMODCACHE "$scratch/go/pkg/mod" \
    --setenv GOFLAGS -mod=vendor --setenv GOPROXY off --setenv GOSUMDB off --setenv GOTOOLCHAIN local \
    --setenv npm_config_cache "$scratch/cache/npm" --setenv npm_config_offline true --setenv npm_config_update_notifier false \
    --setenv PIP_NO_INDEX 1 --setenv PIP_CACHE_DIR "$scratch/cache/pip" \
    --setenv CARGO_HOME "$scratch/cargo" --setenv CARGO_NET_OFFLINE true \
    "${set_env[@]}" \
    -- "$@"
