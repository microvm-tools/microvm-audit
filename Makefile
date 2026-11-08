# make audit.run TARGET=<repo> AUDIT_OUT=<dir> [REV=<rev>] [PROMPT="…"]
#
# The run's containment comes from the profile in flake.nix, not from here:
# these are the only variables the command reads.
NIX_FLAGS ?= --accept-flake-config
export NIXPKGS_ALLOW_UNFREE := 1

.PHONY: audit.run build check

audit.run:
	@test -n "$(TARGET)" && test -n "$(AUDIT_OUT)" || { echo "usage: make audit.run TARGET=<repo> AUDIT_OUT=<dir> [REV=<rev>] [PROMPT=\"…\"]" >&2; exit 64; }
	nix run --impure $(NIX_FLAGS) .#default -- --target "$(TARGET)" --out "$(AUDIT_OUT)" \
	  $(if $(REV),--rev "$(REV)") $(if $(PROMPT),--prompt "$(PROMPT)")

build:
	nix build --impure $(NIX_FLAGS) .#default

check:
	nix flake check --impure $(NIX_FLAGS) --max-jobs 1
