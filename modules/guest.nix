# The audit guest, on top of claude-microvm's claude flavor (lib.mkRunner):
#
#   - /audit-out, the only host-writable share: reports and evidence;
#   - the pinned skill as root-owned copies in Claude Code's managed skills
#     directory, where the agent cannot change it and nothing it fetches
#     could replace it;
#   - managed settings that keep the target's own Claude configuration out
#     (its hooks, MCP servers, skills and agents would run as the agent,
#     outside audit-sandbox), and deny the model's server-side web tools;
#   - the toolchain, and audit-sandbox for running target code;
#   - microvm-audit-agent instead of plain `claude`: the run's prompt, and
#     the session transcript kept beside the report.
{ skill, skillInfo, sandbox, profile, toolchain }:
{ config, lib, pkgs, ... }:

let
  skillDir = "${skill}/${skillInfo.path}";
  skillName = "security-audit";
  managedDir = "claude-code";

  # Copied, not symlinked: a symlinked skill directory is not reliably
  # discovered, and a copy in /etc is root's.
  skillFiles = map (f: builtins.unsafeDiscardStringContext (lib.removePrefix "${skillDir}/" (toString f)))
    (lib.filesystem.listFilesRecursive skillDir);
  skillEtc = lib.listToAttrs (map (f: lib.nameValuePair "${managedDir}/.claude/skills/${skillName}/${f}" {
    source = "${skillDir}/${f}";
    mode = "0444";
  }) skillFiles);

  # Nothing in the user's or the project's settings overrides a managed key.
  managedSettings = {
    # Skills, agents, hooks and MCP servers only from managed sources: the
    # target's .claude/ and .mcp.json are data to audit, not configuration.
    strictPluginOnlyCustomization = true;
    allowManagedHooksOnly = true;
    allowManagedMcpServersOnly = true;
    disableSideloadFlags = true;
    # The target's CLAUDE.md files are data to audit, not instructions.
    claudeMdExcludes = [ "/work/**" ];
    permissions.deny = [
      # Web search runs on the model provider's side, past the egress proxy
      # and its audit log; fetches would be denied by the proxy anyway.
      "WebSearch"
      "WebFetch"
    ];
  };

  instructions = pkgs.writeText "audit-instructions.md" ''
    # This environment

    You are running the security-audit skill in a sealed VM built for it.

    - The target is /work: an export of the repository at one commit,
      without git history. Changes you make there stay in this VM.
    - The output directory for this run is given in the request. It lies
      below /audit-out, the only place whose contents outlive the VM; earlier
      runs of the same target are beside it. Write nothing you need to keep
      anywhere else: your home directory is discarded with the VM.
    - There is no network except the model API. Nothing can be downloaded or
      installed; the toolchain on PATH (go, node, python3, gcc, make, git) is
      all there is. Go runs offline (GOPROXY=off, GOTOOLCHAIN=local).

    # Executing target code

    Every target-controlled process (a build, a test, a fuzzer, a script or
    fixture from the repository) runs through audit-sandbox, never directly:

        audit-sandbox --scratch <output-dir>/agents/<agent-id>/scratch -- <command> [args...]

    It provides the controls the skill requires: no network (loopback only,
    so the target cannot reach the model API), an empty environment with
    HOME, TMPDIR and caches inside the scratch directory, the target (--source,
    default /work) and the toolchain read-only, the scratch directory the only
    writable path, and memory, process, CPU, file-size and wall-clock limits.
    It refuses (exit 125) rather than run with less; exit 124 means the wall
    clock ran out. `audit-sandbox --describe` prints its controls and limits
    as JSON for the records. A build that must write beside its sources runs
    on a copy inside the scratch directory, with --cwd pointing there.
  '';

  agent = pkgs.writeShellApplication {
    name = "microvm-audit-agent";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      # Started by the guest's console in place of `claude`, with the
      # launcher's AGENTS_ARGS: --run <name> --target <name> --commit <sha>
      # --prompt <text>.
      run="" target="" commit="" prompt=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --run) run="$2"; shift 2 ;;
          --target) target="$2"; shift 2 ;;
          --commit) commit="$2"; shift 2 ;;
          --prompt) prompt="$2"; shift 2 ;;
          *) echo "microvm-audit-agent: unknown argument: $1" >&2; exit 2 ;;
        esac
      done
      [[ "$run" =~ ^run-[0-9]+$ ]] || { echo "microvm-audit-agent: no run name" >&2; exit 2; }
      out="/audit-out/$run"
      [ -d "$out" ] || { echo "microvm-audit-agent: $out does not exist" >&2; exit 2; }

      # The skill is invoked by name, so it loads whatever the model makes of
      # the request; the rest of the line is its argument.
      request="/${skillName} $prompt

      Target: /work, the repository $target at commit $commit.
      Output directory for this run: $out (full audit mode). Earlier runs of
      this target, if any, are the other run-* directories in /audit-out."

      cd /work
      status=0
      # --setting-sources user: the target's .claude/settings.json is not
      # read at all. Managed settings alone do not stop it: its apiKeyHelper
      # runs a command, as the agent and outside audit-sandbox. Managed
      # settings still apply.
      claude --setting-sources user --dangerously-skip-permissions --append-system-prompt "$(cat ${instructions})" \
        -p "$request" || status=$?

      # What the agent did, beside what it reported: the session transcripts.
      # They are the agent's own account, written in the guest.
      if [ -d "$HOME/.claude/projects" ]; then
        mkdir -p "$out/transcript"
        cp -r "$HOME/.claude/projects/." "$out/transcript/" || true
      fi
      echo "microvm-audit-agent: claude exited $status"
      exit "$status"
    '';
  };
in
{
  claude-vm.shares.audit-out = { mountPoint = "/audit-out"; readOnly = false; };

  claude-vm.agent.mem = profile.mem;
  claude-vm.agent.vcpu = profile.vcpu;
  claude-vm.store.size = profile.storeSize;
  claude-vm.agent.launchCommand = lib.mkForce "microvm-audit-agent";

  environment.systemPackages = toolchain ++ [ sandbox agent ];

  environment.etc = skillEtc // {
    "${managedDir}/managed-settings.json" = {
      text = builtins.toJSON managedSettings;
      mode = "0444";
    };
  };

  # The agent's own Go commands are offline too, as the sandbox's are.
  environment.variables = {
    GOPROXY = "off";
    GOSUMDB = "off";
    GOTOOLCHAIN = "local";
  };
}
