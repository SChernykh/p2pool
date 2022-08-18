{
  description = "Decentralized pool for Monero mining.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
    let
    pkgs = import nixpkgs { inherit system; };
    in
    rec {
      packages = utils.lib.flattenTree {
        p2pool =  pkgs.stdenv.mkDerivation {
          pname = "p2pool";
          version = "0.0.1";
          src = self;

          nativeBuildInputs = builtins.attrValues {
            inherit (pkgs) cmake pkg-config;
          };

          buildInputs = builtins.attrValues {
            inherit (pkgs) libuv zeromq libsodium gss curl;
          };

          installPhase = ''
            mkdir -p $out/bin
            cp -r ./p2pool $out/bin/
          '';
        };
      };

      defaultPackage = packages.p2pool;
    }
  );
}
