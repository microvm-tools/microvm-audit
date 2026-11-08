# The audit guest, from its evaluated NixOS configuration (nothing boots):
#
#   - /audit-out is its one extra share, and writable;
#   - the console starts microvm-audit-agent, not plain claude;
#   - every file of the pinned skill is a root-owned copy (mode 0444, so not
#     a symlink) in Claude Code's managed skills directory;
#   - the managed settings keep the target's Claude configuration and its
#     CLAUDE.md files out and deny the server-side web tools, and the agent
#     can read them (a managed file it cannot read is silently ignored);
#   - the agent reads no project settings at all (--setting-sources user);
#   - audit-sandbox and the toolchain are on PATH; memory and vCPUs follow
#     the profile.
{ pkgs, lib, audit, skillInfo, skill }:

let
  cfg = audit.runner.nixosConfig.config;
  etc = cfg.environment.etc;
  skillPrefix = "claude-code/.claude/skills/security-audit/";
  skillKeys = lib.filter (lib.hasPrefix skillPrefix) (lib.attrNames etc);
  pinned = map (f: builtins.unsafeDiscardStringContext (lib.removePrefix "${skill}/${skillInfo.path}/" (toString f)))
    (lib.filesystem.listFilesRecursive "${skill}/${skillInfo.path}");
  managedEntry = etc."claude-code/managed-settings.json";
  managed = builtins.fromJSON managedEntry.text;
  agentScript = lib.findFirst (p: lib.getName p == "microvm-audit-agent") (throw "no microvm-audit-agent on PATH") cfg.environment.systemPackages;

  checks = [
    {
      name = "the audit-out share is the only extra share, writable at /audit-out";
      ok = cfg.claude-vm.shares == { audit-out = { mountPoint = "/audit-out"; readOnly = false; }; };
    }
    {
      name = "the console starts microvm-audit-agent";
      ok = cfg.claude-vm.agent.launchCommand == "microvm-audit-agent";
    }
    {
      name = "every file of the pinned skill is in the managed skills directory, and nothing else";
      ok = lib.sort lib.lessThan (map (lib.removePrefix skillPrefix) skillKeys) == lib.sort lib.lessThan pinned
        && lib.elem "SKILL.md" pinned;
    }
    {
      name = "each is a copy (mode 0444), not a symlink into the store";
      ok = lib.all (n: etc.${n}.mode == "0444") skillKeys;
    }
    {
      name = "managed settings: skills, agents, hooks and MCP servers only from managed sources";
      ok = managed.strictPluginOnlyCustomization == true && managed.allowManagedHooksOnly == true
        && managed.allowManagedMcpServersOnly == true && managed.disableSideloadFlags == true;
    }
    {
      name = "managed settings exclude the target's CLAUDE.md files";
      ok = managed.claudeMdExcludes == [ "/work/**" ];
    }
    {
      name = "managed settings deny WebSearch and WebFetch";
      ok = lib.elem "WebSearch" managed.permissions.deny && lib.elem "WebFetch" managed.permissions.deny;
    }
    {
      name = "managed settings are a world-readable copy";
      ok = managedEntry.mode == "0444";
    }
    {
      name = "audit-sandbox is on PATH";
      ok = lib.elem audit.sandbox cfg.environment.systemPackages;
    }
    {
      name = "the guest's memory and vCPUs are the profile's";
      ok = cfg.claude-vm.agent.mem == audit.profile.mem && cfg.claude-vm.agent.vcpu == audit.profile.vcpu;
    }
    {
      name = "Go is offline for the agent too";
      ok = cfg.environment.variables.GOPROXY == "off" && cfg.environment.variables.GOTOOLCHAIN == "local";
    }
  ];
in
pkgs.runCommand "guest" { } ''
  fail=0
  ${lib.concatMapStrings (c:
    if c.ok then ''echo ${lib.escapeShellArg "ok: ${c.name}"}
    '' else ''echo ${lib.escapeShellArg "FAIL: ${c.name}"} >&2; fail=1
    '') checks}
  # The target's .claude/settings.json must not be read: its apiKeyHelper
  # would run a command as the agent, which managed settings do not stop.
  if grep -q -- 'claude --setting-sources user ' ${agentScript}/bin/microvm-audit-agent; then
    echo "ok: the agent runs claude with --setting-sources user"
  else echo "FAIL: the agent runs claude without --setting-sources user" >&2; fail=1; fi
  [ "$fail" -eq 0 ] || exit 1
  touch $out
''
