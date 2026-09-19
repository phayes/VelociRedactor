{
  description = "Veloci Redactor: redact secrets and PII from text and structured files";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSystem = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkPackage =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "velociredactor";
          version = "0.1.1";

          src = lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              let
                rel = lib.removePrefix (toString ./. + "/") (toString path);
              in
              lib.cleanSourceFilter path type
              && rel != "target"
              && !lib.hasPrefix "target/" rel
              && !lib.hasPrefix "plugin/libexec" rel
              && !lib.hasPrefix "result" rel;
          };

          cargoLock.lockFile = ./Cargo.lock;

          # aws-lc-sys (via hf-hub / reqwest) and onig_sys need a C toolchain.
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.pkg-config
            pkgs.rustPlatform.bindgenHook
          ];

          cargoBuildFlags = [ "--package" "velociredactor-cli" ];
          cargoTestFlags = [ "--workspace" ];

          meta = {
            description = "Redact secrets and PII from text and structured files";
            homepage = "https://github.com/phayes/velociredactor";
            license = lib.licenses.mit;
            mainProgram = "veloci";
          };
        };
    in
    {
      packages = forEachSystem (pkgs: rec {
        velociredactor = mkPackage pkgs;
        veloci = velociredactor;
        default = velociredactor;
      });

      apps = forEachSystem (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.system}.default;
        };
      });

      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.system}.default ];
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer
          ];
        };
      });
    };
}
