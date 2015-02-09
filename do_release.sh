#!/usr/bin/sh

if [ -z "$1" ]; then
    echo "New version not given";
    exit 1;
fi

VERSION=$1


echo "I'm not running anything, run this by yourself"

last=`git tag -l|tail -n1`

echo git-dch --release \
    --new-version=${VERSION} \
    --verbose \
    --commit \
    --since=\"$last\"

echo git tag -s $VERSION

echo python setup.py sdist upload

echo mkdir /tmp/BUILD
echo cp dist/keystone-voms-${VERSION}.tar.gz /tmp/BUILD/python-keystone-voms_${VERSION}.orig.tar.gz
echo cd /tmp/BUILD
echo tar zxfv python-keystone-voms_${VERSION}.orig.tar.gz
echo debuild -S -sa
