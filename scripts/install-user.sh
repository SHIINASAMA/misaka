#!/bin/sh
set -eu

die() {
    echo "install-user.sh: $*" >&2
    exit 1
}

home=${HOME:-}
[ -n "$home" ] || die "HOME is not set"

for command_name in cmp cp dirname grep head mkdir mktemp mv rm sed; do
    command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_binary=$script_dir/misaka
[ -f "$source_binary" ] && [ -x "$source_binary" ] \
    || die "executable misaka binary not found beside the installer: $source_binary"

root_dir=${MISAKA:-"$home/.misaka"}
bin_dir=${MISAKA_BIN_DIR:-"$root_dir/bin"}
stable_binary=${MISAKA_BIN:-"$bin_dir/misaka"}
version=${MISAKA_VERSION:-}

if [ -z "$version" ]; then
    version=$(
        "$source_binary" version --json \
            | sed -n 's/.*"binary_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1
    )
fi
[ -n "$version" ] || die "could not determine the binary CalVer version"
printf '%s\n' "$version" | grep -Eq '^[0-9]{4}\.[1-9][0-9]*\.[1-9][0-9]*$' \
    || die "invalid binary version: $version"

version_dir=$bin_dir/$version
versioned_binary=$version_dir/misaka
mkdir -p "$version_dir" "$(dirname "$stable_binary")"

if [ -e "$versioned_binary" ]; then
    cmp -s "$source_binary" "$versioned_binary" \
        || die "versioned binary already exists with different content: $versioned_binary"
else
    versioned_tmp=$(mktemp "$versioned_binary.tmp.XXXXXX")
    cleanup_versioned() {
        rm -f "$versioned_tmp"
    }
    trap cleanup_versioned EXIT HUP INT TERM
    cp "$source_binary" "$versioned_tmp"
    chmod 0755 "$versioned_tmp"
    mv "$versioned_tmp" "$versioned_binary"
    trap - EXIT HUP INT TERM
fi

stable_tmp=$(mktemp "$stable_binary.tmp.XXXXXX")
cleanup_stable() {
    rm -f "$stable_tmp"
}
trap cleanup_stable EXIT HUP INT TERM
cp "$versioned_binary" "$stable_tmp"
chmod 0755 "$stable_tmp"
mv -f "$stable_tmp" "$stable_binary"
trap - EXIT HUP INT TERM

echo "Installed Misaka $version at $stable_binary"
echo "Retained versioned binary at $versioned_binary"
case ":${PATH:-}:" in
    *:"$(dirname "$stable_binary")":*) ;;
    *) echo "Add it to the current shell with: export PATH=\"$(dirname "$stable_binary"):\$PATH\"" ;;
esac
if ! "$stable_binary" version --json; then
    echo "Run '$stable_binary version' to inspect the installed binary." >&2
fi
echo "Next steps:"
echo "  export MISAKA=\"$root_dir\""
echo "  export MISAKA_CONFIG_DIR=\"\${MISAKA_CONFIG_DIR:-\$MISAKA}\""
echo "  export MISAKA_LOG_DIR=\"\${MISAKA_LOG_DIR:-\$MISAKA/log}\""
echo "  $stable_binary network init       # first host only"
echo "  $stable_binary service install   # uses this stable binary path"
echo "  $stable_binary doctor"
