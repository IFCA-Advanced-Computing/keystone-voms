#!/usr/bin/sh

if [ -z "$1" ]; then
    echo "New version not given";
    exit 1;
fi

VERSION=$1


echo "I'm not running anything, run this by yourself"

echo git-dch \
    --release \
    --new-version=$VERSION \
    --verbose 

echo git tag -s $VERSION


echo python setup.py sdist upload
