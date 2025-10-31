{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "ego-secstorage-env-shell";

  buildInputs = [
    pkgs.go
    pkgs.docker
    pkgs.kubectl
    pkgs.kind
    pkgs.openssl
    pkgs.git
  ];

  shellHook = ''
    echo "Congrats🚀 You entered Nix-shell for EGo Secure Storage Environment by nanashikimi"
    echo ""
    echo "Provided with following packages:"
    echo "   go:      $(go version 2>/dev/null || echo 'not found')"
    echo "   docker:  $(docker --version 2>/dev/null || echo 'not found')"
    echo "   kubectl: $(kubectl version --client 2>/dev/null | grep 'Client Version' || echo 'not found')"
    echo ""
    echo "Note: Remember that ego/ego-go is NOT provided by default, so ensure that ego is in PATH if needed. Maybe it will be realized via Makefile or improved Nix-shell in ongoing versions)"
  '';
}

