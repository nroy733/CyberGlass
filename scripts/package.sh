#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/package.sh [--version VERSION] [--target linux-x86_64] [--no-rpm]

Builds a Linux release binary when needed, then creates a .tar.gz distribution.
On Linux, an RPM is also built by default; rpmbuild is required. Use --no-rpm
to create only the tarball.
EOF
}

VERSION=""
TARGET=""
BUILD_RPM=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { echo "Missing value for --version" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --target)
            [ "$#" -ge 2 ] || { echo "Missing value for --target" >&2; exit 2; }
            TARGET="$2"
            shift 2
            ;;
        --no-rpm)
            BUILD_RPM=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$(uname -s)" != "Linux" ]; then
    if [ "$BUILD_RPM" -eq 1 ]; then
        echo "RPM packaging requires Linux. Use --no-rpm to create a POSIX tarball only." >&2
        exit 1
    fi
fi

if [ -z "$VERSION" ]; then
    VERSION="$(awk '
        /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && /^version[[:space:]]*=/ {
            gsub(/["[:space:]]/, "", $3)
            print $3
            exit
        }
    ' Cargo.toml)"
fi

if [ -z "$VERSION" ]; then
    echo "Could not determine the workspace version; pass --version." >&2
    exit 1
fi

ARCH="$(uname -m)"
if [ "$ARCH" = "amd64" ]; then
    ARCH="x86_64"
elif [ "$ARCH" = "arm64" ]; then
    ARCH="aarch64"
fi
TARGET="${TARGET:-linux-${ARCH}}"
if [ "$TARGET" != "linux-${ARCH}" ]; then
    echo "Target ${TARGET} does not match this host's Linux architecture (linux-${ARCH})." >&2
    echo "Cross-compilation is not configured by this packaging script." >&2
    exit 1
fi
PACKAGE_NAME="cyberglass-v${VERSION}-${TARGET}"
DIST_DIR="dist"
STAGING_DIR="${DIST_DIR}/${PACKAGE_NAME}"
SERVER_BINARY="target/release/cyberglass-server"

if [ ! -x "$SERVER_BINARY" ]; then
    echo "Building release server binary..."
    cargo build --release --bin cyberglass-server
fi

if [ ! -x "$SERVER_BINARY" ]; then
    echo "Release server binary not found or not executable: $SERVER_BINARY" >&2
    exit 1
fi

if [ ! -f "config/cyberglass.toml" ] || [ ! -f "LICENSE" ] || [ ! -f "installer/install.sh" ]; then
    echo "Required packaging input is missing (config, LICENSE, or installer)." >&2
    exit 1
fi

if [ "$BUILD_RPM" -eq 1 ] && ! command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild is required to create the RPM. Install the RPM build tools or use --no-rpm." >&2
    exit 1
fi

mkdir -p "$DIST_DIR"
rm -rf -- "$STAGING_DIR"
mkdir -p "$STAGING_DIR/bin" "$STAGING_DIR/config" "$STAGING_DIR/rules"
install -m 0755 "$SERVER_BINARY" "$STAGING_DIR/bin/cyberglass-server"
install -m 0644 "config/cyberglass.toml" "$STAGING_DIR/config/cyberglass.toml"
install -m 0755 "installer/install.sh" "$STAGING_DIR/install.sh"
install -m 0644 "LICENSE" "$STAGING_DIR/LICENSE"
install -m 0644 "README.md" "$STAGING_DIR/README.md"
install -m 0644 "DEPLOYMENT.md" "$STAGING_DIR/DEPLOYMENT.md"
cp -R "docs" "$STAGING_DIR/docs"
if [ -d "rules" ]; then
    cp -R "rules/." "$STAGING_DIR/rules/"
fi

cat > "$STAGING_DIR/README.txt" <<EOF
CyberGlass SIEM — Linux distribution
Version: ${VERSION}
Target: ${TARGET}

Install on Linux:
    sudo ./install.sh

Install in the current user's home directory:
    ./install.sh --user

Run without installing:
    ./bin/cyberglass-server --home .

Web interface: http://localhost:9401
EOF

TARBALL="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
rm -f -- "$TARBALL"
tar -czf "$TARBALL" -C "$DIST_DIR" "$PACKAGE_NAME"
echo "Created $TARBALL"

if [ "$BUILD_RPM" -eq 1 ]; then
    case "$TARGET" in
        linux-*) ;;
        *)
            echo "RPM target must be Linux, got: $TARGET" >&2
            exit 1
            ;;
    esac

    RPM_TOP="${DIST_DIR}/rpmbuild"
    rm -rf -- "$RPM_TOP"
    mkdir -p "$RPM_TOP/BUILD" "$RPM_TOP/BUILDROOT" "$RPM_TOP/RPMS" \
        "$RPM_TOP/SOURCES" "$RPM_TOP/SPECS" "$RPM_TOP/SRPMS"
    install -m 0644 "$TARBALL" "$RPM_TOP/SOURCES/cyberglass-bundle.tar.gz"
    install -m 0644 "packaging/rpm/cyberglass.spec" "$RPM_TOP/SPECS/cyberglass.spec"
    install -m 0644 "packaging/rpm/cyberglass.service" "$RPM_TOP/SOURCES/cyberglass.service"

    rpmbuild -bb \
        --define "_topdir ${RPM_TOP}" \
        --define "version_override ${VERSION}" \
        "$RPM_TOP/SPECS/cyberglass.spec"

    RPM_ARCH="$(rpm --eval '%{_arch}')"
    RPM_SOURCE="${RPM_TOP}/RPMS/${RPM_ARCH}/cyberglass-${VERSION}-1.${RPM_ARCH}.rpm"
    RPM_PACKAGE="${DIST_DIR}/cyberglass-v${VERSION}-${TARGET}.rpm"
    if [ ! -f "$RPM_SOURCE" ]; then
        echo "rpmbuild did not produce the expected RPM: $RPM_SOURCE" >&2
        exit 1
    fi
    install -m 0644 "$RPM_SOURCE" "$RPM_PACKAGE"
    echo "Created $RPM_PACKAGE"
fi
