# microvm-audit, the host command, with the launcher replaced by a stand-in
# that writes a launch record from the environment it was given — so a
# setting the command got wrong shows in the record, and the evidence check
# has to catch it:
#
#   - the launcher gets the profile's settings and nothing of the caller's
#     environment beyond a short list: no EXTRA_ENV, no allowlist, no other
#     agent's key, whatever the caller exported;
#   - the workspace is the commit's tracked files, not the working tree;
#   - each run gets the next run-<N>, and the agent its request intact;
#   - a clean run is valid (0); a verdict that is not clean, a record that
#     shows less containment than the profile, or no record at all is
#     invalid (2); a run cut short or failed is incomplete (3);
#   - the evidence is kept on the host and copied beside the report;
#   - what cannot work is refused before any launch.
{ pkgs, lib, skillInfo, defaultProfile }:

let
  fakeRunner = pkgs.writeShellApplication {
    name = "microvm-run";
    runtimeInputs = [ pkgs.jq pkgs.coreutils pkgs.findutils ];
    text = ''
      # What it was given, for the test to look at.
      env | sort > "$HOME/runner.env"
      pwd > "$HOME/runner.cwd"
      (cd "$WORK_DIR" && find . -type f | sort) > "$HOME/runner.files"
      printf %s "$AGENTS_ARGS" > "$HOME/runner.args"
      cat "$WORK_DIR/VERSION" > "$HOME/runner.version"
      scenario="$(cat "$HOME/scenario" 2>/dev/null || echo .)"
      [ "$scenario" = norecord ] && exit 1
      rec="$(jq -n \
        --arg policy "''${EGRESS_POLICY:-open}" --arg builtin "''${EGRESS_BUILTIN:-1}" \
        --arg br "''${API_BUDGET_REQUESTS:-}" --arg bt "''${API_BUDGET_TOKENS:-}" \
        --arg wm "''${WORKSPACE_MODE:-passthrough}" --arg guard "''${WORKSPACE_GUARD:-0}" --arg am "''${AGENT_HOME_MODE:-persistent}" \
        --arg share "''${SHARE_AUDIT_OUT:-}" --arg key "''${ANTHROPIC_API_KEY:-}" --arg extra "''${EXTRA_ENV:-}" \
        --arg mem "''${VM_MEM:-8192}" --arg vcpu "''${VM_VCPU:-4}" --arg t "''${VM_TIMEOUT:-0}" --arg grace "''${VM_TIMEOUT_GRACE:-60}" '
        {egress: {policy: $policy, builtinAllowlists: ($builtin == "1"), deny: [],
                  endpoints: [{prefix: "/anthropic"}],
                  apiBudget: (if $br == "" and $bt == "" then null else {maxRequests: ($br | tonumber), maxTokens: ($bt | tonumber)} end)},
         workspace: {dir: "x", mode: $wm, guard: ($guard == "1")},
         agentHome: {dir: "y", mode: $am},
         shares: [{name: "audit-out", host: $share, guest: "/audit-out", readOnly: false, socket: "s", unit: "u"}],
         env: {apiKeys: (if $key == "" then [] else ["ANTHROPIC_API_KEY"] end),
               extraEnv: (if $extra == "" then [] else ($extra | split(",")) end), devShellFromHost: false},
         resources: {memMiB: ($mem | tonumber), vcpus: ($vcpu | tonumber)},
         timeout: (if $t == "0" then null else {seconds: ($t | tonumber), graceSeconds: ($grace | tonumber)} end),
         ended: {exitStatus: 0, timedOut: false, egressVerdict: {outcome: "clean", summary: "egress verdict: clean"}, apiUsage: []}}')"
      jq "$scenario" <<< "$rec" > "$LAUNCH_RECORD"
      echo "fake launcher: done"
      exit "$(jq -r .ended.exitStatus "$LAUNCH_RECORD")"
    '';
  };
  audit = pkgs.callPackage ../pkgs/microvm-audit.nix {
    runner = pkgs.runCommand "fake-runner" { } "mkdir -p $out/bin; ln -s ${fakeRunner}/bin/microvm-run $out/bin/microvm-run";
    profile = defaultProfile;
    inherit skillInfo;
  };
in
pkgs.runCommand "wrapper" { nativeBuildInputs = [ pkgs.git pkgs.jq ]; } ''
  fail=0
  ok ()  { echo "ok: $1"; }
  bad () { echo "FAIL: $1" >&2; fail=1; }

  export HOME=$TMPDIR/home XDG_STATE_HOME=$TMPDIR/state XDG_CACHE_HOME=$TMPDIR/cache
  mkdir -p $HOME
  export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

  T=$TMPDIR/domain-backend
  mkdir -p $T/cmd && cd $T && git init -q
  echo 'package main' > cmd/main.go; echo v1 > VERSION
  git add -A && git commit -q -m one
  first=$(git rev-parse HEAD)
  echo v2 > VERSION; git commit -q -am two
  echo dirty > VERSION; echo untracked > notes.txt
  cd $TMPDIR

  OUT=$TMPDIR/audits/domain-backend
  # What a caller might have exported, none of which may reach the launcher.
  export ANTHROPIC_API_KEY=sk-test OPENAI_API_KEY=sk-other EXTRA_ENV=FOO=bar EGRESS_ALLOW=evil.example.com \
         EGRESS_POLICY=open DIRENV_ALLOW=1 AGENT_HOME=/tmp/x WORKSPACE_MODE=passthrough VM_MEM=1 LAUNCH_RECORD=/tmp/r
  a () { rc=0; ${audit}/bin/microvm-audit "$@" > $TMPDIR/out.log 2>&1 || rc=$?; }
  ev () { jq -r "$1" "$(ls -d $XDG_STATE_HOME/microvm-audit/runs/*-$2/evidence.json)"; }

  # --- a clean run ---------------------------------------------------------------------
  a --target $T --out $OUT --prompt 'audit cmd/ for "auth" bugs; $(not a command)'
  [ $rc = 0 ] && [ "$(ev .status run-1)" = valid ] && [ "$(ev '.failed | length' run-1)" = 0 ] \
    && ok "a clean run is valid (exit 0)" || { bad "clean run: rc $rc"; cat $TMPDIR/out.log >&2; }
  [ -f $OUT/run-1/evidence/evidence.json ] && [ -f $OUT/run-1/evidence/launch-record.json ] && [ -f $OUT/run-1/evidence/session.log ] \
    && grep -q 'fake launcher: done' $OUT/run-1/evidence/session.log \
    && ok "the evidence is kept on the host and copied beside the report, with the session log" || bad "evidence files: $(ls -R $OUT)"
  [ "$(ev .target.commit run-1)" = "$(git -C $T rev-parse HEAD)" ] && [ "$(ev .skill.rev run-1)" = ${skillInfo.rev} ] \
    && [ "$(ev .skill.narHash run-1)" = ${lib.escapeShellArg skillInfo.narHash} ] \
    && ok "the evidence names the target commit and the skill's rev and tree hash" || bad "evidence ids: $(ev '{target, skill}' run-1)"

  # --- what the launcher was given ------------------------------------------------------
  E=$HOME/runner.env
  for v in EGRESS_POLICY=enforce EGRESS_BUILTIN=0 WORKSPACE_MODE=ephemeral WORKSPACE_GUARD=1 AGENT_HOME_MODE=ephemeral \
           CRI_STORAGE_SIZE=0 NO_PAUSE=1 VM_MEM=${toString defaultProfile.mem} VM_TIMEOUT=${toString defaultProfile.timeoutSeconds} \
           API_BUDGET_TOKENS=${toString defaultProfile.budgetTokens} SHARE_AUDIT_OUT=$OUT ANTHROPIC_API_KEY=sk-test; do
    grep -qx "$v" $E || bad "launcher env lacks $v: $(grep "^''${v%%=*}=" $E)"
  done
  if grep -qE '^(OPENAI_API_KEY|EXTRA_ENV|EGRESS_ALLOW|DIRENV_ALLOW|AGENT_HOME|GIT_AUTHOR_NAME)=' $E; then
    bad "the caller's environment reached the launcher: $(grep -E '^(OPENAI_API_KEY|EXTRA_ENV|EGRESS_ALLOW|DIRENV_ALLOW|AGENT_HOME|GIT_AUTHOR_NAME)=' $E)"
  else ok "the launcher gets the profile's settings and none of the caller's"; fi
  [ "$(cat $HOME/runner.files)" = "$(printf './VERSION\n./cmd/main.go')" ] && [ "$(cat $HOME/runner.version)" = v2 ] \
    && ok "the workspace is the commit's tracked files: no uncommitted change, no untracked file" || bad "workspace: $(cat $HOME/runner.files)"
  eval "set -- $(cat $HOME/runner.args)"
  [ "$1 $2 $3 $4 $5" = "--run run-1 --target domain-backend --commit" ] && [ "$6" = "$(git -C $T rev-parse HEAD)" ] \
    && [ "$7" = --prompt ] && [ "$8" = 'audit cmd/ for "auth" bugs; $(not a command)' ] \
    && ok "the agent gets the run, target, commit and the request intact" || bad "agent args: $(cat $HOME/runner.args)"
  [ ! -e "$(dirname $(grep ^WORK_DIR= $E | cut -d= -f2))" ] && ok "the exported tree is removed afterwards" || bad "stage left behind"

  # --- runs add up -----------------------------------------------------------------------
  a --target $T --out $OUT --rev $first
  [ $rc = 0 ] && [ -d $OUT/run-2 ] && [ "$(ev .target.commit run-2)" = $first ] \
    && ok "the next run is run-2, and --rev picks the commit" || bad "second run: rc $rc, $(ls $OUT)"

  # --- what makes a run invalid or incomplete --------------------------------------------
  scenario () { printf '%s' "$1" > $HOME/scenario; }
  scenario '.ended.egressVerdict = {outcome: "not-clean", summary: "NOT CLEAN"}'
  a --target $T --out $OUT
  [ $rc = 2 ] && [ "$(ev .status run-3)" = invalid ] && [ "$(ev '.failed[0]' run-3)" = "egress verdict clean" ] \
    && ok "a verdict that is not clean makes the run invalid (exit 2)" || bad "not clean: rc $rc, $(ev .failed run-3)"
  scenario '.egress.policy = "shadow" | .env.extraEnv = ["FOO"]'
  a --target $T --out $OUT
  [ $rc = 2 ] && [ "$(ev '.failed | join(",")' run-4)" = "egress enforce,environment: the API key only" ] \
    && ok "a record showing less containment than the profile is invalid, naming each gap" || bad "weaker record: rc $rc, $(ev .failed run-4)"
  scenario '.ended.timedOut = true | .ended.exitStatus = 124'
  a --target $T --out $OUT
  [ $rc = 3 ] && [ "$(ev .status run-5)" = incomplete ] \
    && ok "a run the wall clock cut short is incomplete (exit 3)" || bad "timed out: rc $rc, $(ev .status run-5)"
  scenario norecord
  a --target $T --out $OUT
  [ $rc = 2 ] && [ "$(ev '.failed[0]' run-6)" = "launch record written" ] \
    && ok "a launch that left no record is invalid" || bad "no record: rc $rc"
  scenario .

  # --- refused before any launch ---------------------------------------------------------
  refused () { # description, then args; ANTHROPIC_API_KEY as set
    local d=$1; shift
    rm -f $HOME/runner.env
    a "$@"
    [ $rc != 0 ] && [ ! -e $HOME/runner.env ] && ok "refused before launch: $d" || bad "not refused: $d (rc $rc)"
  }
  refused "a target that is not a repository" --target $TMPDIR --out $OUT
  refused "a rev that is not a commit" --target $T --out $OUT --rev nope
  refused "an output directory inside the target" --target $T --out $T/audit
  refused "evidence inside the output directory" --target $T --out $OUT --evidence $OUT/ev
  ANTHROPIC_API_KEY= refused "no API key" --target $T --out $OUT

  [ "$fail" -eq 0 ] || exit 1
  touch $out
''
