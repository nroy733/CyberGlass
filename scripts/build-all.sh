#!/usr/bin/env bash
# ==============================================================================
# 🛡️ CYBERGLASS — Cross-Platform Build & Package Script
# ==============================================================================
# Builds CyberGlass for all supported platforms and creates air-gap distribution
# packages. Run this on any platform to build all targets.
#
# Supported targets:
#   - Linux x86_64 (musl static - runs on any Linux)
#   - Linux ARM64 (musl static)
#   - macOS x86_64
#   - macOS arm64 (Apple Silicon)
#   - Windows x86_64
# ==============================================================================

set -euo pipefail

VERSION="0.2.0"
CARGO="${CARGO:-cargo}"
RUSTUP="${RUSTUP:-rustup}"

echo "============================================================================="
echo "🛡️  CYBERGLASS — Cross-Platform Build & Package"
echo "============================================================================="
echo "Version: ${VERSION}"
echo ""

# Function to add a Rust target if not already installed
add_target() {
    local target="$1"
    if ! rustc --print target-list | grep -q "^${target}$"; then
        echo "  Target ${target} not supported by this rustc installation"
        return 1
    fi
    if ! rustup target list --installed 2>/dev/null | grep -q "^${target}$"; then
        echo "  Installing target ${target}..."
        rustup target add "${target}"
    else
        echo "  Target ${target} already installed"
    fi
}

# Build for a specific target
build_target() {
    local target="$1"
    local name="$2"
    
    echo ""
    echo "============================================================================="
    echo "Building ${name} (${target})..."
    echo "============================================================================="
    
    add_target "${target}" || {
        echo "  ⚠️  Skipping ${target} - target not available"
        return 0
    }
    
    ${CARGO} build --release --target "${target}" --bin cyberglass-server
    
    local binary_path="target/${target}/release/cyberglass-server"
    if [ "${target}" = "x86_64-pc-windows-msvc" ]; then
        binary_path="target/${target}/release/cyberglass-server.exe"
    fi
    
    if [ -f "${binary_path}" ]; then
        echo "  ✔ Binary built: ${binary_path}"
    else
        echo "  ✘ Build failed for ${target}"
        return 1
    fi
    
    echo "${binary_path}"
}

# Stage a distribution package
stage_package() {
    local target="$1"
    local package_name="$2"
    local binary_path="$3"
    local staging_dir="dist/${package_name}"
    
    echo ""
    echo "============================================================================="
    echo "Staging package: ${package_name}"
    echo "============================================================================="
    
    mkdir -p "${staging_dir}/bin"
    mkdir -p "${staging_dir}/config"
    mkdir -p "${staging_dir}/rules"
    mkdir -p "${staging_dir}/installer"
    
    # Copy binary
    cp -f "${binary_path}" "${staging_dir}/bin/"
    chmod +x "${staging_dir}/bin/cyberglass-server" 2>/dev/null || true
    
    # Copy configuration
    if [ -f "config/cyberglass.toml" ]; then
        cp -f "config/cyberglass.toml" "${staging_dir}/config/"
    fi
    
    # Copy documentation
    if [ -d "docs" ]; then
        cp -rf docs "${staging_dir}/"
    fi
    if [ -f "DEPLOYMENT.md" ]; then
        cp -f "DEPLOYMENT.md" "${staging_dir}/"
    fi
    if [ -f "README.md" ]; then
        cp -f "README.md" "${staging_dir}/"
cp -f "LICENSE" "${staging_dir}/"
    fi
    
    # Copy detection rules
    if [ -d "rules" ]; then
        cp -rf rules/* "${staging_dir}/rules/" 2>/dev/null || true
    fi
    
    # Copy installers
    if [ -f "installer/install.sh" ]; then
        cp -f "installer/install.sh" "${staging_dir}/install.sh"
        chmod +x "${staging_dir}/install.sh"
    fi
    if [ -f "installer/install.ps1" ]; then
        cp -f "installer/install.ps1" "${staging_dir}/install.ps1"
    fi
    if [ -f "installer/install.bat" ]; then
        cp -f "installer/install.bat" "${staging_dir}/install.bat"
    fi
    
    # Create quick-start README
    cat > "${staging_dir}/README.txt" << EOF
==============================================================================
🛡️ CYBERGLASS SIEM & DATA FUSION PLATFORM — AIR-GAP DISTRIBUTION
==============================================================================

Target Platform: ${target}
Version: ${VERSION}

To install on Linux or macOS:
    sudo ./install.sh

To install without root privileges (User Mode):
    ./install.sh --user

To install on Windows:
    powershell -ExecutionPolicy Bypass -File .\install.ps1

To start manually without installing:
    ./bin/cyberglass-server --home .

Search & REST Gateway Web UI will be available at:
    http://localhost:9401

For full documentation and architecture:
    ./docs/README.md
    ./DEPLOYMENT.md
==============================================================================
EOF
    
    echo "✔ Package staged: ${staging_dir}"
}

# Package as archive
package_archive() {
    local package_name="$1"
    local dist_dir="dist"
    
    cd "${dist_dir}"
    
    case "${package_name}" in
        *-windows-*)
            Compress-Archive -Path "${package_name}\*" -DestinationPath "${package_name}.zip" -Force 2>/dev/null || \
                7z a -tzip "${package_name}.zip" "${package_name}\*" 2>/dev/null || \
                zip -r "${package_name}.zip" "${package_name}"
            echo "✔ Package created: dist/${package_name}.zip"
            ;;
        *)
            tar -czvf "${package_name}.tar.gz" "${package_name}"
            echo "✔ Package created: dist/${package_name}.tar.gz"
            ;;
    esac
    
    cd ..
}

# Main build process
echo "📦 Step 1: Adding Rust targets..."
add_target "x86_64-unknown-linux-musl" || true
add_target "aarch64-unknown-linux-musl" || true
add_target "aarch64-apple-darwin" || true
add_target "x86_64-apple-darwin" || true
add_target "x86_64-pc-windows-msvc" || true

echo ""
echo "📦 Step 2: Building all targets..."

# Build Linux x86_64 (musl - runs on any Linux)
BIN_LINUX_X64=$(build_target "x86_64-unknown-linux-musl" "Linux x86_64 (musl)") || true

# Build Linux ARM64 (musl)
BIN_LINUX_ARM64=$(build_target "aarch64-unknown-linux-musl" "Linux ARM64 (musl)") || true

# Build macOS x86_64
BIN_DARWIN_X86=$(build_target "x86_64-apple-darwin" "macOS x86_64") || true

# Build macOS ARM64
BIN_DARWIN_ARM64=$(build_target "aarch64-apple-darwin" "macOS ARM64") || true

# Build Windows x86_64
BIN_WINDOWS_X64=$(build_target "x86_64-pc-windows-msvc" "Windows x86_64") || true

echo ""
echo "============================================================================="
echo "📦 Step 3: Staging distribution packages..."
echo "============================================================================="

# Stage packages
if [ -f "${BIN_LINUX_X64}" ]; then
    stage_package "x86_64-unknown-linux-musl" "cyberglass-v${VERSION}-linux-x86_64" "${BIN_LINUX_X64}"
fi

if [ -f "${BIN_LINUX_ARM64}" ]; then
    stage_package "aarch64-unknown-linux-musl" "cyberglass-v${VERSION}-linux-arm64" "${BIN_LINUX_ARM64}"
fi

if [ -f "${BIN_DARWIN_X86}" ]; then
    stage_package "x86_64-apple-darwin" "cyberglass-v${VERSION}-darwin-x86_64" "${BIN_DARWIN_X86}"
fi

if [ -f "${BIN_DARWIN_ARM64}" ]; then
    stage_package "aarch64-apple-darwin" "cyberglass-v${VERSION}-darwin-arm64" "${BIN_DARWIN_ARM64}"
fi

if [ -f "${BIN_WINDOWS_X64}" ]; then
    stage_package "x86_64-pc-windows-msvc" "cyberglass-v${VERSION}-windows-x86_64" "${BIN_WINDOWS_X64}"
fi

echo ""
echo "============================================================================="
echo "📦 Step 4: Creating distribution archives..."
echo "============================================================================="

# Package archives
[ -d "dist/cyberglass-v${VERSION}-linux-x86_64" ] && \
    cd dist && tar -czvf "cyberglass-v${VERSION}-linux-x86_64.tar.gz" "cyberglass-v${VERSION}-linux-x86_64" && cd ..

[ -d "dist/cyberglass-v${VERSION}-linux-arm64" ] && \
    cd dist && tar -czvf "cyberglass-v${VERSION}-linux-arm64.tar.gz" "cyberglass-v${VERSION}-linux-arm64" && cd ..

[ -d "dist/cyberglass-v${VERSION}-darwin-x86_64" ] && \
    cd dist && tar -czvf "cyberglass-v${VERSION}-darwin-x86_64.tar.gz" "cyberglass-v${VERSION}-darwin-x86_64" && cd ..

[ -d "dist/cyberglass-v${VERSION}-darwin-arm64" ] && \
    cd dist && tar -czvf "cyberglass-v${VERSION}-darwin-arm64.tar.gz" "cyberglass-v${VERSION}-darwin-arm64" && cd ..

[ -d "dist/cyberglass-v${VERSION}-windows-x86_64" ] && \
    cd dist && Compress-Archive -Path "cyberglass-v${VERSION}-windows-x86_64\*" -DestinationPath "cyberglass-v${VERSION}-windows-x86_64.zip" -Force 2>/dev/null || \
    cd dist && 7z a -tzip "cyberglass-v${VERSION}-windows-x86_64.zip" "cyberglass-v${VERSION}-windows-x86_64\"* 2>/dev/null || \
    cd dist && zip -r "cyberglass-v${VERSION}-windows-x86_64.zip" "cyberglass-v${VERSION}-windows-x86_64" 2>/dev/null && cd ..

echo ""
echo "============================================================================="
echo "✔ BUILD COMPLETE"
echo "============================================================================="
echo ""
echo "Distribution packages:"
ls -la dist/*.tar.gz dist/*.zip 2>/dev/null || echo "  No packages found"
echo ""
echo "To install:"
echo "  Linux/macOS: ./install.sh"
echo "  Windows:     powershell -ExecutionPolicy Bypass -File .\install.ps1"
echo ""
echo "To run the Web UI:"
echo "  http://localhost:9401"
echo ""