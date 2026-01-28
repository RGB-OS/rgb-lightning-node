{
  description = "Dev shell for rgb-lightning-node (tests + openssl + docker compose)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        openssl = pkgs.openssl;
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.rustc
            pkgs.cargo
            pkgs.clippy
            pkgs.rustfmt
            pkgs.pkg-config
            pkgs.gcc
            pkgs.cmake
            pkgs.clang    # for cc / ld.lld
            openssl
            pkgs.zlib
            pkgs.docker-client
            pkgs.docker-compose
            pkgs.git
          ];

          shellHook = ''
            export OPENSSL_DIR=${openssl.dev}
            export OPENSSL_LIB_DIR=${openssl.out}/lib
            export OPENSSL_INCLUDE_DIR=${openssl.dev}/include
            export PKG_CONFIG_PATH=${openssl.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
            export OPENSSL_NO_VENDOR=1
            echo "Toolchain: using nixpkgs rustc/cargo; skip rustup to avoid ld-wrapper issues."
          '';
        };
      });
}
