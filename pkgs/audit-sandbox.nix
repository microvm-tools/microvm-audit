{ lib, writeShellApplication, bubblewrap, util-linux, coreutils, gnugrep, systemd, toolchain, defaults, scratchRoot ? "/audit-out" }:

writeShellApplication {
  name = "audit-sandbox";
  runtimeInputs = [ bubblewrap util-linux coreutils gnugrep systemd ];
  text = lib.replaceStrings
    [ "@SCRATCH_ROOT@" "@TIME@" "@MEM@" "@TASKS@" "@CPUS@" "@FSIZE@" "@TOOLPATH@" ]
    [ scratchRoot (toString defaults.timeSeconds) (toString defaults.memMiB) (toString defaults.tasks)
      (toString defaults.cpus) (toString defaults.fileSizeMiB) (lib.makeBinPath toolchain) ]
    (builtins.readFile ../scripts/audit-sandbox.sh);
}
