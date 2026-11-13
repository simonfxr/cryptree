{
  description = "cryptree";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      flib = flake-utils.lib;
      pkg =
        pkgs:
        pkgs.buildGo127Module {
          name = "cryptree";
          version = "0.0.1";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./go.mod
              ./go.sum
              (pkgs.lib.fileset.fileFilter (f: f.hasExt "go") ./.)
            ];
          };
          vendorHash = "sha256-Qw2OKs8ntwYhwmPdtZ6FwTwiiu5IWaowANDiD8kNw+U=";
          env.CGO_ENABLED = "0";
          ldflags = [
            "-s"
            "-w"
          ];
          buildFlags = [ "-trimpath" ];
          subPackages = [ "cmd/cryptree" ];
        };
    in
    flib.eachSystem flib.defaultSystems (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ];
        };
      in
      rec {
        packages.default = packages.cryptree;
        packages.cryptree = pkg pkgs;
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_27
            pkgs.gopls
          ];
        };
      }
    )
    // {
      overlays.default = final: prev: { cryptree = pkg final; };
    };
}
