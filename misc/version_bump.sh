#!/bin/sh

PROGNAME=$0

VHEAD='src/core/angie.h'
CHANGES='docs/xml/angie/changes.xml'

die()
{
    echo "$PROGNAME: error: $@" >&2
    rm -f "$VHEAD.tmp" "$CHANGES.tmp"
    exit 1
}

if [ $# -lt 1 ]; then
    echo "Usage: $0 {major|minor|patch}" >&2
    exit 1
fi

if [ ! -f "$VHEAD" ] || [ ! -f "$CHANGES" ]; then
    die "must be run from Angie root directory"
fi

if [ ! -d ".hg/patches" ]; then
    die "MQ not initialized"
fi

if [ -n "$(hg status -mard)" ]; then
    hg status -mard
    die "there are uncommitted changes in the working directory"
fi

res=$(awk '
/define ANGIE_VERSION/ {
    if (!match($3, /"([0-9]+)\.([0-9]+)\.([0-9]+)"/, m)) {
        exit(1);
    }
    printf("major=%s;minor=%s;patch=%s;\n", m[1], m[2], m[3]);
    found=1;
    exit;
}
END { if (!found) { exit(1); } }
' "$VHEAD") || die "failed to extract ANGIE_VERSION from $VHEAD"

eval $res

ORIG_VERSION="$major.$minor.$patch"

case "$1" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "Usage: $0 {major|minor|patch}" >&2; exit 1 ;;
esac

NEW_VERSION="$major.$minor.$patch"

awk -v major=$major -v minor=$minor -v patch=$patch '
/define ANGIE_VERSION/ {
    printf("#define ANGIE_VERSION      \"%s.%s.%s\"\n", major, minor, patch);
    replaced_str = 1;
    next;
}
/define angie_version/ {
    num = major * 1000000 + minor * 1000 + patch;
    printf("#define angie_version      %s\n", num);
    replaced_num = 1;
    next;
}
{ print $0; }
END { if (!replaced_str || !replaced_num) { exit(1); } }
' "$VHEAD" > "$VHEAD.tmp" || die "failed to update version in $VHEAD"


awk -v ver="$NEW_VERSION" '
{ print($0); }
/<change_log title="Angie">/ {
    printf("\n\n<changes ver=\"%s\" date=\"\">\n\n</changes>\n", ver);
    injected = 1;
}
END { if (!injected) { exit(1); } }
' "$CHANGES" > "$CHANGES.tmp" || die "failed to updated $CHANGES"

mv "$VHEAD.tmp" "$VHEAD"
mv "$CHANGES.tmp" "$CHANGES"

hg qnew -m "Version bump to $NEW_VERSION." "version-bump-$NEW_VERSION"

echo "Version bump $ORIG_VERSION -> $NEW_VERSION ($1) completed"
