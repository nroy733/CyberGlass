# ==============================================================================
# 🛡️ CYBERGLASS — Multi-OS Build & Packaging Automation
# ==============================================================================

VERSION := 0.1.0
CARGO := cargo

.PHONY: all build release test clean package-all package-linux package-darwin package-windows

all: build

# Local compilation
build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --release --bin cyberglass-server

test:
	$(CARGO) test --workspace

# Linux 100% Statically-Linked musl (Runs on ANY Linux distro without dependencies)
build-linux-static:
	rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
	$(CARGO) build --release --target x86_64-unknown-linux-musl --bin cyberglass-server

# Linux ARM64 (AWS Graviton, Ampere, Raspberry Pi)
build-linux-arm64:
	rustup target add aarch64-unknown-linux-musl 2>/dev/null || true
	$(CARGO) build --release --target aarch64-unknown-linux-musl --bin cyberglass-server

# macOS Apple Silicon (M1/M2/M3/M4)
build-darwin-arm64:
	rustup target add aarch64-apple-darwin 2>/dev/null || true
	$(CARGO) build --release --target aarch64-apple-darwin --bin cyberglass-server

# macOS Intel
build-darwin-x86:
	rustup target add x86_64-apple-darwin 2>/dev/null || true
	$(CARGO) build --release --target x86_64-apple-darwin --bin cyberglass-server

# Windows x86_64
build-windows:
	$(CARGO) build --release --target x86_64-pc-windows-msvc --bin cyberglass-server 2>/dev/null || \
	$(CARGO) build --release --bin cyberglass-server

# Assemble air-gap deployment tarballs
package-linux:
	@bash scripts/package.sh linux-x86_64

package-darwin-arm64:
	@bash scripts/package.sh darwin-arm64

package-darwin-x86:
	@bash scripts/package.sh darwin-x86_64

package-windows:
	@powershell -ExecutionPolicy Bypass -File scripts/package.ps1

package-all: package-linux package-darwin-arm64 package-darwin-x86 package-windows

clean:
	$(CARGO) clean
	rm -rf dist/
