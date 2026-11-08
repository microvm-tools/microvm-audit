{
  description = "microvm-audit: a contained, no-egress security-audit run of a pinned skill against a repository, in a claude-microvm VM";

  nixConfig = {
    extra-substituters = [ "https://microvm-tools.cachix.org" "https://systemstart.cachix.org" "https://microvm.cachix.org" ];
    extra-trusted-public-keys = [
      "microvm-tools.cachix.org-1:OmNkdhRACxrceImh52cuegLuzJCj5hZFwFA8scRBk7A="
      "systemstart.cachix.org-1:hSTfDlXstyuVVukogR0sEmt8wJsaplp7NvisgUugNpE="
      "microvm.cachix.org-1:oXnBc6hRE3eX5rSYdRyMYXnfzcCxC7yKPTbZXALsqys="
    ];
  };

  inputs = {
    claude-vm.url = "github:microvm-tools/agent-vm/v0.19.0";

    # The skill: third-party instructions, so pinned to a commit and never
    # fetched by the agent. flake.lock's narHash is its tree hash, which Nix
    # checks on every fetch; the run's evidence records rev and narHash.
    skill = {
      url = "github:cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";
      flake = false;
    };
  };

  outputs = { self, claude-vm, skill }:
    let
      nixpkgs = claude-vm.inputs.nixpkgs;
      lib = nixpkgs.lib;
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});

      # What every run gets, and nothing on the command line changes. A
      # different profile is a different build: lib.mkAudit { profile = …; }.
      defaultProfile = {
        mem = 12288;               # MiB
        vcpu = 6;
        storeSize = 20480;         # MiB, the guest's writable Nix store disk
        timeoutSeconds = 10800;    # wall clock (3h), then the power button
        timeoutGraceSeconds = 120;
        budgetRequests = 5000;     # per model endpoint, the proxy refuses past it
        budgetTokens = 30000000;   # input, cache and output together
        # Sandboxed target processes: the defaults audit-sandbox applies.
        sandbox = { timeSeconds = 600; memMiB = 2048; tasks = 256; cpus = 2; fileSizeMiB = 256; };
      };

      # The toolchain target code is built and tested with, offline. The same
      # set is on the agent's PATH, so what it inspects is what the sandbox runs.
      defaultToolchain = pkgs: with pkgs; [
        bashInteractive coreutils findutils diffutils gnugrep gnused gawk gnutar gzip xz which file
        git gnumake gcc pkg-config go nodejs python3
      ];

      skillInfo = {
        repo = "https://github.com/cloudflare/security-audit-skill";
        rev = skill.rev;
        narHash = skill.narHash;
        path = "skills/security-audit";
      };

      mkAudit = { system, profile ? defaultProfile, toolchain ? defaultToolchain, modules ? [ ] }:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          sandbox = pkgs.callPackage ./pkgs/audit-sandbox.nix {
            toolchain = toolchain pkgs;
            defaults = profile.sandbox;
          };
          runner = claude-vm.lib.mkRunner {
            inherit system;
            flavor = "claude";
            modules = [
              (import ./modules/guest.nix { inherit skill skillInfo sandbox profile; toolchain = toolchain pkgs; })
            ] ++ modules;
          };
        in
        pkgs.callPackage ./pkgs/microvm-audit.nix { inherit runner profile skillInfo; }
        // { inherit runner sandbox profile; };
    in
    {
      lib = { inherit mkAudit defaultProfile defaultToolchain; };

      packages = forSystems (system: pkgs:
        let audit = mkAudit { inherit system; }; in {
          default = audit;
          microvm-audit = audit;
          audit-sandbox = audit.sandbox;
          runner = audit.runner;
        });

      checks = forSystems (system: pkgs:
        let audit = self.packages.${system}.default; in {
          wrapper = import ./tests/wrapper.nix { inherit pkgs lib skillInfo defaultProfile; };
          guest = import ./tests/guest.nix { inherit pkgs lib audit skillInfo skill; };
        } // lib.optionalAttrs (system == "x86_64-linux") {
          sandbox = import ./tests/sandbox.nix { inherit pkgs lib; sandbox = audit.sandbox; };
        });

      devShells = forSystems (system: pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.shellcheck pkgs.jq ]; };
      });
    };
}
