#!/usr/bin/env bash
# Renders the AUR PKGBUILD for one release and proves it builds.
#
# usage: aur.sh <dlsentinel_*_all.deb> <outdir>
#
# Fills PKGBUILD.in with the version, the release download URL and the
# sha256 of the .deb, then, in an archlinux:latest container, generates
# .SRCINFO, runs makepkg (the .deb is placed next to the PKGBUILD under its
# release name, so makepkg verifies the checksum without downloading), runs
# namcap, installs the result and runs the same smoke test as verify.sh.
# Writes <name>-bin-<version>-aur.tar.gz holding PKGBUILD and .SRCINFO,
# ready to push to the AUR.
#
# The release carries the .deb as <name>_<version>_all.deb: the Debian
# version has a "~" (0.1.0~noble1), which GitHub would rename on upload.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
[ $# -eq 2 ] || { echo "usage: $0 <deb> <outdir>" >&2; exit 2; }
deb="$(readlink -f "$1")"
mkdir -p "$2"; out="$(cd "$2" && pwd)"
# shellcheck source=/dev/null
. "$here/../linux-distros/distro.conf"
: "${VERSION:?set VERSION}"
: "${GITHUB_REPO:?distro.conf must set GITHUB_REPO}"
tag="${TAG_PREFIX-v}$VERSION"
deb_name="${NAME}_${VERSION}_all.deb"
case "$(dpkg-deb -f "$deb" Version)" in
  "$VERSION" | "$VERSION"~*) ;;
  *) echo "$deb is version $(dpkg-deb -f "$deb" Version), not $VERSION" >&2; exit 1 ;;
esac

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
deps=""; for d in "${ARCH_DEPENDS[@]}"; do deps+="'$d' "; done
sed -e "s|@NAME@|$NAME|g" -e "s|@VERSION@|$VERSION|g" \
    -e "s|@SUMMARY@|${SUMMARY//\'/}|g" -e "s|@HOMEPAGE@|$HOMEPAGE|g" \
    -e "s|@LICENSE@|$LICENSE|g" -e "s|@ARCH_DEPENDS@|${deps% }|g" \
    -e "s|@RELEASE_URL@|https://github.com/$GITHUB_REPO/releases/download/$tag|g" \
    -e "s|@DEB@|$deb_name|g" \
    -e "s|@SHA256@|$(sha256sum "$deb" | cut -d' ' -f1)|g" \
    "$here/PKGBUILD.in" > "$work/PKGBUILD"
cp "$deb" "$work/$deb_name"
if grep -n '@[A-Z0-9_]*@' "$work/PKGBUILD"; then echo "unfilled placeholder" >&2; exit 1; fi
cat "$work/PKGBUILD"

docker run --rm -v "$work:/build" -v "$here/../linux-distros:/linux-distros:ro" \
  -v "$repo:/src:ro" -e SMOKE_CMD="$SMOKE_CMD" archlinux:latest bash -euo pipefail -c '
  pacman -Syu --noconfirm --needed -q base-devel namcap
  useradd -m builder
  chown -R builder /build
  cd /build
  su builder -c "makepkg --printsrcinfo > .SRCINFO"
  su builder -c "makepkg --noconfirm --nodeps -f"
  namcap PKGBUILD ./*-any.pkg.tar.zst
  pacman -U --noconfirm ./*-any.pkg.tar.zst
  bash -c "$SMOKE_CMD"
  cat .SRCINFO
'
tar -C "$work" -czf "$out/$NAME-bin-$VERSION-aur.tar.gz" PKGBUILD .SRCINFO
ls -l "$out/$NAME-bin-$VERSION-aur.tar.gz"
