{ lib, writeShellApplication, coreutils, git, gnutar, jq, runner, profile, skillInfo }:

writeShellApplication {
  name = "microvm-audit";
  runtimeInputs = [ coreutils git gnutar jq ];
  text = lib.replaceStrings
    [ "@RUNNER@" "@PROFILE@" "@SKILL@" ]
    [ "${runner}/bin/microvm-run" (builtins.toJSON profile) (builtins.toJSON skillInfo) ]
    (builtins.readFile ../scripts/microvm-audit.sh);
}
