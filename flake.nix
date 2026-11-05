{
  description = "WebRTC development shell";

  inputs.nix-overlays.url = "github:nix-ocaml/nix-overlays";

  outputs =
    { nix-overlays, ... }:
    {
      devShells = nix-overlays.lib.genAttrs nix-overlays.lib.systems.flakeExposed (
        system:
        let
          pkgs = nix-overlays.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              pkg-config
              openssl
            ];
          };
        }
      );
    };
}
