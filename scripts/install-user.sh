#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_binary=$script_dir/misaka
install_dir=${MISAKA_INSTALL_DIR:-"$HOME/.local/bin"}
destination=$install_dir/misaka

if [ ! -f "$source_binary" ] || [ ! -x "$source_binary" ]; then
    echo "install-user.sh: executable misaka binary not found beside the installer: $source_binary" >&2
    exit 1
fi

mkdir -p "$install_dir"
temporary=$(mktemp "$install_dir/.misaka.tmp.XXXXXX")
cleanup() {
    rm -f "$temporary"
}
trap cleanup EXIT HUP INT TERM

cp "$source_binary" "$temporary"
chmod 0755 "$temporary"
mv -f "$temporary" "$destination"
trap - EXIT HUP INT TERM

echo "Installed Misaka at $destination"
if ! "$destination" version --json; then
    echo "Run '$destination version' to inspect the installed binary." >&2
fi
echo "Next steps:"
echo "  $destination network init       # first host only"
echo "  $destination service install   # uses this stable binary path"
echo "  $destination doctor"
