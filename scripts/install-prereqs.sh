#!/bin/bash

#set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

INSTALL_FALCO=false
SKIP_PY_DEPS=false

for arg in "$@"; do
  case "$arg" in
    --with-falco)
      INSTALL_FALCO=true
      ;;
    --skip-python-deps)
      SKIP_PY_DEPS=true
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/install-prereqs.sh [options]

Options:
  --with-falco        Install Falco (runtime monitoring prerequisite)
  --skip-python-deps  Skip pip requirements installation
  -h, --help          Show this help message
EOF
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $arg${NC}"
      exit 1
      ;;
  esac
done

log() {
  echo -e "${CYAN}==>${NC} $1"
}

ok() {
  echo -e "${GREEN}✓${NC} $1"
}

warn() {
  echo -e "${YELLOW}!${NC} $1"
}

fail() {
  echo -e "${RED}✗${NC} $1"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1
}

detect_platform() {
  local os
  os="$(uname -s)"
  case "$os" in
    Linux*) PLATFORM="linux" ;;
    Darwin*) PLATFORM="darwin" ;;
    *) fail "Unsupported OS: $os (supported: Linux, macOS)" ;;
  esac
}

setup_installer() {
  if require_cmd apt-get; then
    PKG_MANAGER="apt"
  elif require_cmd dnf; then
    PKG_MANAGER="dnf"
  elif require_cmd yum; then
    PKG_MANAGER="yum"
  elif require_cmd pacman; then
    PKG_MANAGER="pacman"
  elif require_cmd zypper; then
    PKG_MANAGER="zypper"
  elif require_cmd brew; then
    PKG_MANAGER="brew"
  else
    fail "No supported package manager found (apt, dnf, yum, pacman, zypper, brew)."
  fi

  if [[ "$PKG_MANAGER" == "brew" ]]; then
    SUDO=""
  elif [[ $(id -u) -ne 0 ]]; then
    if require_cmd sudo; then
      SUDO="sudo"
    else
      fail "This script needs root privileges. Install sudo or run as root."
    fi
  else
    SUDO=""
  fi
}

pkg_update() {
  case "$PKG_MANAGER" in
    apt) $SUDO apt-get update ;;
    dnf) $SUDO dnf makecache ;;
    yum) $SUDO yum makecache ;;
    pacman) $SUDO pacman -Sy ;;
    zypper) $SUDO zypper refresh ;;
    brew) brew update ;;
  esac
}

pkg_install() {
  case "$PKG_MANAGER" in
    apt) $SUDO apt-get install -y "$@" ;;
    dnf) $SUDO dnf install -y "$@" ;;
    yum) $SUDO yum install -y "$@" ;;
    pacman) $SUDO pacman -S --noconfirm "$@" ;;
    zypper) $SUDO zypper install -y "$@" ;;
    brew) brew install "$@" ;;
  esac
}

install_base_tools() {
  log "Installing core prerequisites (git, curl, make, Python, Go, Docker, kubectl, minikube)..."

  case "$PKG_MANAGER" in
    apt)
      pkg_install git curl make ca-certificates gnupg lsb-release python3 python3-pip golang-go docker.io kubectl minikube
      ;;
    dnf)
      pkg_install git curl make python3 python3-pip golang docker kubernetes-client minikube
      ;;
    yum)
      pkg_install git curl make python3 python3-pip golang docker kubectl minikube
      ;;
    pacman)
      pkg_install git curl make python python-pip go docker kubectl minikube
      ;;
    zypper)
      pkg_install git curl make python3 python3-pip go docker kubernetes-client minikube
      ;;
    brew)
      pkg_install git curl make python go docker kubectl minikube
      ;;
  esac

  ok "Core tools installed"
}

install_falco() {
  if [[ "$INSTALL_FALCO" != "true" ]]; then
    warn "Skipping Falco installation (use --with-falco to install it)."
    return
  fi

  log "Installing Falco..."
  case "$PKG_MANAGER" in
    apt)
      curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | $SUDO gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
      echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | $SUDO tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null
      $SUDO apt-get update
      $SUDO apt-get install -y falco
      ;;
    dnf|yum)
      $SUDO rpm --import https://falco.org/repo/falcosecurity-packages.asc
      $SUDO curl -s -o /etc/yum.repos.d/falcosecurity.repo https://download.falco.org/packages/rpm/falcosecurity.repo
      pkg_install falco
      ;;
    pacman)
      warn "Falco package is not officially available via pacman in all distros. Install via Helm or binary: https://falco.org/docs/"
      ;;
    zypper)
      warn "Falco package setup for zypper is distro-specific. Install manually: https://falco.org/docs/"
      ;;
    brew)
      brew install falco
      ;;
  esac

  ok "Falco installation step complete"
}

install_python_deps() {
  if [[ "$SKIP_PY_DEPS" == "true" ]]; then
    warn "Skipping Python dependencies (--skip-python-deps)."
    return
  fi

  local root_req="${ROOT_DIR}/requirements.txt"
  local ai_req="${ROOT_DIR}/ai-module/requirements.txt"

  log "Installing Python dependencies from requirements files..."

  if [[ ! -f "$root_req" ]]; then
    fail "Missing file: $root_req"
  fi

  python3 -m pip install --upgrade pip
  python3 -m pip install -r "$root_req"

  if [[ -f "$ai_req" ]]; then
    if grep -qE '^(<<<<<<<|=======|>>>>>>>)' "$ai_req"; then
      warn "Merge conflict markers found in ai-module/requirements.txt; skipping that file."
      warn "Resolve the conflict, then run: python3 -m pip install -r ai-module/requirements.txt"
    else
      python3 -m pip install -r "$ai_req"
    fi
  fi

  ok "Python dependencies installed"
}

configure_docker() {
  if ! require_cmd docker; then
    warn "Docker command not found after install step."
    return
  fi

  if [[ "$PLATFORM" == "linux" ]]; then
    if require_cmd systemctl; then
      log "Enabling and starting Docker service..."
      $SUDO systemctl enable docker >/dev/null 2>&1 || true
      $SUDO systemctl start docker >/dev/null 2>&1 || true
    fi

    if [[ -n "${SUDO}" ]] && [[ -n "${USER:-}" ]]; then
      $SUDO usermod -aG docker "$USER" >/dev/null 2>&1 || true
      warn "If this is your first Docker setup, log out/in for docker group changes to apply."
    fi
  fi

  ok "Docker post-install configuration complete"
}

verify_tools() {
  log "Verifying installed prerequisites..."

  local missing=0
  local tools=(go python3 pip3 docker kubectl minikube)

  for tool in "${tools[@]}"; do
    if require_cmd "$tool"; then
      ok "$tool found"
    else
      warn "$tool not found"
      missing=1
    fi
  done

  if [[ "$INSTALL_FALCO" == "true" ]]; then
    if require_cmd falco; then
      ok "falco found"
    else
      warn "falco not found"
      missing=1
    fi
  fi

  echo
  if [[ $missing -eq 0 ]]; then
    ok "All selected prerequisites are installed."
  else
    warn "Some tools are still missing. Check warnings above and install manually if needed."
  fi

  echo
  echo -e "${CYAN}Version Summary:${NC}"
  go version 2>/dev/null || true
  python3 --version 2>/dev/null || true
  pip3 --version 2>/dev/null || true
  docker --version 2>/dev/null || true
  kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null || true
  minikube version 2>/dev/null || true
  if [[ "$INSTALL_FALCO" == "true" ]]; then
    falco --version 2>/dev/null || true
  fi
}

main() {
  echo -e "${CYAN}============================================${NC}"
  echo -e "${CYAN} KubeSentinel Prerequisites Installer ${NC}"
  echo -e "${CYAN}============================================${NC}"
  echo

  [[ -f "${ROOT_DIR}/go.mod" ]] || fail "Run this script inside the KubeSentinel repository."

  detect_platform
  log "Detected platform: $PLATFORM"

  setup_installer
  log "Using package manager: $PKG_MANAGER"

  pkg_update
  install_base_tools
  install_falco
  install_python_deps
  configure_docker
  verify_tools

  echo
  ok "Done. Next: make -f scripts/Makefile deps && make -f scripts/Makefile build"
}

main "$@"
