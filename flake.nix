{
  description = "rust dev shell";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        isDarwin = pkgs.stdenv.isDarwin;
      in
      with pkgs;
      {
        devShells.default = mkShell {
          nativeBuildInputs = [
            # Build tools
            clang
            lld
            pkg-config
            perl
            git

            # Rust toolchain
            rust-bin.nightly.latest.default
            rust-analyzer
          ];

          buildInputs = [
            # Libraries
            openssl
          ] ++ lib.optionals isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        };
      }
    );
}