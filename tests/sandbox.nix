# audit-sandbox in a VM, as the agent user, each control checked from inside
# the sandbox — where target code would look:
#
#   - no network: what listens outside, on the VM's loopback, is out of reach;
#     a server and a client inside share a loopback of their own;
#   - an empty environment: the caller's variables (an API key) are gone;
#     HOME and TMPDIR are inside scratch;
#   - the target read-only; scratch the only writable path; the agent's home,
#     the rest of /audit-out, /run and /tmp absent;
#   - memory, task, file-size and wall-clock limits hold; no nested user
#     namespaces;
#   - refusals: no or a misplaced scratch, a symlinked path, a limit above the
#     profile's, a credential-looking variable, a source that is not a tree.
#
# Every denial is checked with a positive control: the command first prints
# "ran" from inside the sandbox, so a sandbox that failed to start cannot pass
# as one that denied.
{ pkgs, lib, sandbox }:

pkgs.testers.runNixOSTest {
  name = "audit-sandbox";
  nodes.machine = { lib, ... }: {
    virtualisation.memorySize = 2048;
    users.users.agent = { isNormalUser = true; uid = 1000; linger = true; };
    environment.systemPackages = [ sandbox pkgs.python3 ];
    systemd.tmpfiles.rules = [ "d /audit-out 0755 agent users -" ];
    # As in the audit guest: an OOM inside a cgroup kills there. The test
    # framework's panic_on_oom would panic the kernel on any OOM.
    boot.kernel.sysctl."vm.panic_on_oom" = lib.mkForce 0;
  };

  testScript = ''
    import json
    machine.wait_for_unit("user@1000.service")
    S = "/audit-out/run-1/agents/h1/scratch"
    machine.succeed(f"su agent -c 'mkdir -p {S} && echo retained > /audit-out/run-1/findings.json && ln -s {S} /audit-out/run-1/agents/h1/link'")
    machine.succeed("mkdir -p /work && echo 'package main' > /work/main.go")

    def run(args):
        out = machine.succeed(f"su agent -c 'ANTHROPIC_API_KEY=sk-secret audit-sandbox {args}; echo status=$?'")
        lines = out.splitlines()
        return int(lines[-1].split("=")[1]), lines[:-1]

    def sb(args):
        s, out = run(args)
        assert s == 0, f"{args}: status {s}: {out}"
        return out

    def denied(snippet, opts=""):
        # Ran inside the sandbox, then the snippet failed: not refused (125).
        s, out = run(f"--scratch {S} {opts} -- bash -c \"echo ran; {snippet}\"")
        assert "ran" in out and s not in (0, 125), f"{snippet}: status {s}: {out}"

    with subtest("--describe is JSON"):
        d = json.loads(machine.succeed("su agent -c 'audit-sandbox --describe'"))
        assert d["limits"]["memoryMiB"] > 0, d

    with subtest("no network beyond a loopback of its own"):
        machine.succeed("systemd-run --unit=outside python3 -m http.server 8080 --bind 127.0.0.1")
        machine.wait_for_open_port(8080)
        machine.succeed("bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080'")
        denied("exec 3<>/dev/tcp/127.0.0.1/8080")
        sb(f"--scratch {S} -- bash -c \"python3 -m http.server 9090 --bind 127.0.0.1 & for i in \\$(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/9090) 2>/dev/null && exit 0; sleep 0.1; done; exit 1\"")
        ifaces = sb(f"--scratch {S} -- bash -c \"tail -n +3 /proc/net/dev | cut -d: -f1\"")
        assert [i.strip() for i in ifaces] == ["lo"], ifaces

    with subtest("an empty environment, HOME and TMPDIR in scratch"):
        env = sb(f"--scratch {S} --env FOO=bar -- env")
        names = sorted(l.split("=", 1)[0] for l in env if "=" in l)
        assert "ANTHROPIC_API_KEY" not in names and "FOO" in names, names
        assert f"HOME={S}/home" in env and f"TMPDIR={S}/tmp" in env and "GOPROXY=off" in env, env

    with subtest("the target read-only, scratch writable, the rest absent"):
        sb(f"--scratch {S} -- bash -c \"grep -qw package /work/main.go && echo y > {S}/out\"")
        machine.succeed(f"grep -qx y {S}/out")
        denied("echo x > /work/main.go")
        for p in ["/home/agent", "/audit-out/run-1/findings.json", "/run/user", "/tmp"]:
            denied(f"test -e {p}")

    with subtest("limits hold"):
        denied("python3 -c \\\"b = bytearray(256 * 1024 * 1024)\\\"", "--mem 64")
        denied("python3 -c \\\"import os,time; [os.fork() or (time.sleep(3), os._exit(0)) for _ in range(32)]\\\"", "--tasks 8")
        denied(f"head -c 3000000 /dev/zero > {S}/big", "--file-size 1")
        denied("python3 -c \\\"import os; os.unshare(os.CLONE_NEWUSER)\\\"")
        s, out = run(f"--scratch {S} --time 2 -- bash -c \"echo ran; sleep 30\"")
        assert s == 124 and "ran" in out, (s, out)

    with subtest("refusals"):
        for r in [
            "-- true",
            "--scratch /audit-out/run-1 -- true",
            "--scratch /audit-out/run-1/agents/h1/link -- true",
            f"--scratch {S} --mem 999999 -- true",
            f"--scratch {S} --env GITHUB_TOKEN=x -- true",
            f"--scratch {S} --env PATH=/tmp -- true",
            f"--scratch {S} --source /home -- true",
            f"--scratch {S} --source /audit-out/run-1 -- true",
        ]:
            assert run(r)[0] == 125, r
  '';
}
