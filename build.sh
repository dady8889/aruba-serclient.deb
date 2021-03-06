#!/bin/bash
#
# Build Debian package from files.
#

VERSION="0.01"
DEBIAN_RELEASE="3"
# Update changelog.Debian.gz
# Tag the release

set -e

(
    cd CONTENTS
    find usr -type f -exec md5sum "{}" ";" > ../DEBIAN/md5sums
    GZIP="-9 -n" tar czvf ../data.tar.gz ./*
)

(
    cd DEBIAN
    GZIP="-9 -n" tar czvf ../control.tar.gz ./*
)

ar rv aruba-serclient_${VERSION}-${DEBIAN_RELEASE}_all.deb debian-binary control.tar.gz data.tar.gz
rm -f control.tar.gz data.tar.gz

#lintian --display-info --display-experimental --pedantic --show-overrides --no-tag-display-limit --verbose \
#    aruba-serclient_${VERSION}-${DEBIAN_RELEASE}_all.deb
