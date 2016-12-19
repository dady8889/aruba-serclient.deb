#!/bin/bash

VERSION="0.01"
DEBIAN_RELEASE="2"

cd DEBIAN
GZIP="-9" tar czvf ../data.tar.gz *
cd -

cd CONTENTS
GZIP="-9" tar czvf ../control.tar.gz *
cd -

ar rv aruba-serclient_${VERSION}-${DEBIAN_RELEASE}_all.deb debian-binary control.tar.gz data.tar.gz

lintian --display-info --display-experimental --pedantic --show-overrides --no-tag-display-limit --verbose aruba-serclient_${VERSION}-${DEBIAN_RELEASE}_all.deb
