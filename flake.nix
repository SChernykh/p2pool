{
  description = "Decentralized pool for Monero mining.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
  };

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.p2pool =  with import nixpkgs { system = "x86_64-linux";}; stdenv.mkDerivation {
      pname = "p2pool";
      version = "0.0.1";
      src = self;

      nativeBuildInputs = [ cmake pkg-config ];

      buildInputs = [
        libuv zeromq
        libsodium gss
      ];

      installPhase = ''
        mkdir -p $out/bin
        cp -r ./p2pool $out/bin/
      '';
    };

    defaultPackage.x86_64-linux = self.packages.x86_64-linux.p2pool;
  };
}
