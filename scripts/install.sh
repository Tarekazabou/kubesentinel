#!/bin/bash

# KubeSentinel Installation Script for Linux and macOS
# This script builds and installs KubeSentinel CLI tool

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================="
echo -e "KubeSentinel Installation Script"
echo -e "==================================${NC}"
echo ""

# Detect OS
OS=$(uname -s)
case "$OS" in
    Linux*)     PLATFORM="linux" ;;
    Darwin*)    PLATFORM="darwin" ;;
    *)          PLATFORM="UNKNOWN" ;;
esac

echo -e "${YELLOW}Detected OS: $OS (Platform: $PLATFORM)${NC}"

# Check if Go is installed
echo -e "${YELLOW}Checking for Go installation...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${RED}✗ Error: Go is not installed or not in PATH${NC}"
    echo -e "${YELLOW}Please install Go from https://golang.org/dl/${NC}"
    exit 1
fi

GO_VERSION=$(go version)
echo -e "${GREEN}✓ Found: $GO_VERSION${NC}"

# Define installation paths
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="kubesentinel"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

# Check if we need sudo
if [ ! -w "$INSTALL_DIR" ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Get the script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( dirname "$SCRIPT_DIR" )"

# Check if we're in the project directory
if [ ! -f "$PROJECT_ROOT/go.mod" ]; then
    echo -e "${RED}✗ Error: go.mod not found. Please run this script from the project root.${NC}"
    exit 1
fi

# Create a temporary directory for the build
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

echo -e "${YELLOW}Building KubeSentinel...${NC}"
cd "$PROJECT_ROOT"

if go build -o "$BUILD_DIR/$BINARY_NAME" -ldflags "-s -w" ./cmd/kubesentinel; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Handle installation with or without sudo
if [ ! -z "$SUDO" ]; then
    echo -e "${YELLOW}This installation requires elevated privileges.${NC}"
    if [ -f "$BINARY_PATH" ]; then
        echo -e "${YELLOW}Removing existing installation...${NC}"
        $SUDO rm -f "$BINARY_PATH"
    fi
    echo -e "${YELLOW}Installing to $BINARY_PATH...${NC}"
    $SUDO cp "$BUILD_DIR/$BINARY_NAME" "$BINARY_PATH"
    $SUDO chmod +x "$BINARY_PATH"
else
    echo -e "${YELLOW}Installing to $BINARY_PATH...${NC}"
    cp "$BUILD_DIR/$BINARY_NAME" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
fi

# Ensure /usr/local/bin is in path
SHELL_CONFIG=""
if [ -f "$HOME/.zshrc" ] ; then
	SHELL_CONFIG="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ] ; then
	SHELL_CONFIG="HOME/.bashrc"
fi

touch "$SHELL_CONFIG"

if [ -n "$SHELL_CONFIG" ] ; then
	if ! grep -q 'export PATH=.*\/usr\/local\/bin' "$SHELL_CONFIG"; then
		echo 'export PATH=$PATH:/usr/local/bin' >> "$SHELL_CONFIG"
		source "$SHELL_CONFIG"
	fi
fi

# Verify installation
echo -e "${YELLOW}Verifying installation...${NC}"
if [ -f "$BINARY_PATH" ] && [ -x "$BINARY_PATH" ]; then
    echo -e "${GREEN}✓ Binary installed: $BINARY_PATH${NC}"
else
    echo -e "${RED}✗ Binary installation failed${NC}"
    exit 1
fi

# Test the installation
echo -e "${YELLOW}Testing installation...${NC}"
if $BINARY_PATH --version &> /dev/null; then
    echo -e "${GREEN}✓ KubeSentinel is ready to use!${NC}"
    echo ""
    echo -e "${CYAN}Version info:${NC}"
    $BINARY_PATH --version
else
    echo -e "${GREEN}✓ Installation complete. Run 'kubesentinel --help' to get started.${NC}"
fi

echo ""
echo -e "${CYAN}Installation Summary:${NC}"
echo -e "${GREEN}Installation Path:${NC} $INSTALL_DIR"
echo -e "${GREEN}Binary:${NC} $BINARY_PATH"
echo ""
echo -e "${YELLOW}You can now use 'kubesentinel' from anywhere in your terminal.${NC}"
echo -e "${YELLOW}Run: kubesentinel --help${NC}"
