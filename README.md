# Keystone VOMS auth module

[![Travis](https://img.shields.io/travis/IFCA/keystone-voms.svg)](https://travis-ci.org/IFCA/keystone-voms)
[![Coveralls](https://img.shields.io/coveralls/IFCA/keystone-voms.svg)](https://coveralls.io/github/IFCA/keystone-voms)

This module is intended to provide VOMS authentication to a Mitaka
OpenStack Keystone. It is designed to be integrated as an external
authentication plugin, so that Keystone will preserve its original
features and users will still be able to authenticate using any of the
Keystone native mechanisms.

The documentation (the source is in ``doc/source/``) is online at
[Keystone VOMS documentation](https://keystone-voms.readthedocs.org/en/latest/).

If you are using it, it would be nice that you add your site to the
[Sites Using It](https://github.com/IFCA/keystone-voms/wiki/SitesUsingIt) wiki page.

## Testing

If you are interested in running the unit tests, check the ``TESTING.md``
file for instructions.

[Build Status]: https://travis-ci.org/IFCA/keystone-voms
[BS img]: https://travis-ci.org/IFCA/keystone-voms.png
