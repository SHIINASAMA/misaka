#!/bin/sh
set -eu

die() {
    echo "misaka installer: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Install the latest published Misaka release for this macOS/Linux host.

Environment:
  MISAKA_VERSION       Pin the release, for example 2026.9.18.
  MISAKA_INSTALL_DIR   Override the per-user binary directory.

This installs only the binary. It does not initialize a Network, create
~/.misaka, install a service, or configure Gateway/Relay settings.
EOF
}

case "${1:-}" in
    "") ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        die "unexpected argument '$1' (use environment variables; see --help)"
        ;;
esac

home=${HOME:-}
[ -n "$home" ] || die "HOME is not set"

for command_name in awk basename curl find grep head mkdir mktemp rm sed tar uname; do
    command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

if command -v shasum >/dev/null 2>&1; then
    checksum_tool=shasum
elif command -v sha256sum >/dev/null 2>&1; then
    checksum_tool=sha256sum
else
    die "required checksum command not found: shasum or sha256sum"
fi

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
    Darwin:arm64|Darwin:aarch64)
        target=aarch64-apple-darwin
        ;;
    Darwin:x86_64|Darwin:amd64)
        target=x86_64-apple-darwin
        ;;
    Linux:x86_64|Linux:amd64)
        target=x86_64-unknown-linux-gnu
        ;;
    Linux:arm64|Linux:aarch64)
        target=aarch64-unknown-linux-gnu
        ;;
    *)
        die "unsupported host: OS=$os architecture=$arch"
        ;;
esac

requested_version=${MISAKA_VERSION:-}
if [ -n "$requested_version" ]; then
    printf '%s\n' "$requested_version" | grep -Eq '^[0-9]{4}\.[1-9][0-9]*\.[1-9][0-9]*$' \
        || die "MISAKA_VERSION must use CalVer YYYY.M.D without leading zeroes"
fi

if [ -n "${MISAKA_RELEASE_BASE_URL:-}" ]; then
    release_base=$MISAKA_RELEASE_BASE_URL
elif [ -n "$requested_version" ]; then
    release_base="https://github.com/SHIINASAMA/misaka/releases/download/v$requested_version"
else
    release_base="https://github.com/SHIINASAMA/misaka/releases/latest/download"
fi

install_dir=${MISAKA_INSTALL_DIR:-"$home/.local/bin"}
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/misaka-install.XXXXXX")
cleanup() {
    rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

manifest_file=$temporary_root/release-manifest.json

curl -fsSL -o "$manifest_file" -- "$release_base/release-manifest.json" \
    || die "failed to download release-manifest.json from $release_base"

manifest_value() {
    key=$1
    sed -n "s/^[[:space:]]*\"$key\": \"\([^\"]*\)\".*/\1/p" "$manifest_file" | head -n 1
}

manifest_schema=$(sed -n 's/^[[:space:]]*"schema_version": \([0-9][0-9]*\),.*/\1/p' "$manifest_file" | head -n 1)
[ "$manifest_schema" = 1 ] || die "unsupported release manifest schema: ${manifest_schema:-missing}"
manifest_scheme=$(manifest_value version_scheme)
[ "$manifest_scheme" = calver ] || die "unsupported release version scheme: ${manifest_scheme:-missing}"

release_version=$(manifest_value version)
[ -n "$release_version" ] || die "release manifest has no version"
printf '%s\n' "$release_version" | grep -Eq '^[0-9]{4}\.[1-9][0-9]*\.[1-9][0-9]*$' \
    || die "release manifest has an invalid CalVer version: $release_version"

if [ -n "$requested_version" ] && [ "$requested_version" != "$release_version" ]; then
    die "requested version $requested_version but manifest reports $release_version"
fi

asset_name=$(awk -v wanted_target="$target" '
    $0 ~ "\"target\": \"" wanted_target "\"" { in_asset = 1; next }
    in_asset && /"name":/ {
        gsub(/.*"name": "/, "")
        gsub(/".*/, "")
        print
        exit
    }
    in_asset && /^    }/ { exit }
' "$manifest_file")

asset_sha256=$(awk -v wanted_target="$target" '
    $0 ~ "\"target\": \"" wanted_target "\"" { in_asset = 1; next }
    in_asset && /"sha256":/ {
        gsub(/.*"sha256": "/, "")
        gsub(/".*/, "")
        print
        exit
    }
    in_asset && /^    }/ { exit }
' "$manifest_file")

[ -n "$asset_name" ] || die "release $release_version has no asset for target $target"
[ -n "$asset_sha256" ] || die "release manifest has no SHA-256 for target $target"

expected_name="misaka-v${release_version}-${target}.tar.gz"
[ "$asset_name" = "$expected_name" ] \
    || die "release manifest asset name is unexpected: $asset_name"

archive_file=$temporary_root/$asset_name
checksum_file=$temporary_root/$asset_name.sha256
curl -fsSL -o "$archive_file" -- "$release_base/$asset_name" \
    || die "failed to download $asset_name"
curl -fsSL -o "$checksum_file" -- "$release_base/$asset_name.sha256" \
    || die "failed to download $asset_name.sha256"

if [ "$checksum_tool" = shasum ]; then
    (cd "$temporary_root" && shasum -a 256 -c "$(basename "$checksum_file")") \
        || die "SHA-256 verification failed for $asset_name"
else
    (cd "$temporary_root" && sha256sum -c "$(basename "$checksum_file")") \
        || die "SHA-256 verification failed for $asset_name"
fi

if [ "$checksum_tool" = shasum ]; then
    actual_sha256=$(shasum -a 256 "$archive_file" | awk '{print $1}')
else
    actual_sha256=$(sha256sum "$archive_file" | awk '{print $1}')
fi
[ "$actual_sha256" = "$asset_sha256" ] \
    || die "release manifest SHA-256 disagrees with $asset_name.sha256"

extract_dir=$temporary_root/extracted
mkdir -p "$extract_dir"
tar -xzf "$archive_file" -C "$extract_dir" \
    || die "failed to extract $asset_name"

archive_installer=$(find "$extract_dir" -type f -name install-user.sh -print -quit)
[ -n "$archive_installer" ] || die "release archive has no install-user.sh"

MISAKA_INSTALL_DIR="$install_dir" sh "$archive_installer"
installed_binary=$install_dir/misaka
[ -x "$installed_binary" ] || die "installer did not create executable $installed_binary"

echo "Installed Misaka $release_version for $target at $installed_binary"
case ":${PATH:-}:" in
    *:"$install_dir":*) ;;
    *) echo "Add it to the current shell with: export PATH=\"$install_dir:\$PATH\"" ;;
esac
echo "Configuration is separate; no Network or service state was created."
