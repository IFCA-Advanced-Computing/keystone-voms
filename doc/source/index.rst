==============================
Openstack Keystone VOMS module
==============================

This module is intended to provide VOMS authentication to a Grizzly
OpenStack Keystone. It is designed to be integrated as an external
authentication plugin, so that Keystone will preserve its original
features and users will still be able to authenticate using any of the
Keystone native mechanisms.

This documentation is based on an Icehouse installation.

* Only V2 authentication is supported in Icehouse so far.
* If you are using the Grizzly version, please check the `Grizzly
  Documentation <http://keystone-voms.readthedocs.org/en/stable-grizzly/>`_.
  Note that Grizzly does not support usernames longer that 64 characters
  (`Bug #1081932 <https://bugs.launchpad.net/keystone/+bug/1081932>`_).
* If you are using the Havana version, please check the `Havana
  Documentation <http://keystone-voms.readthedocs.org/en/stable-havana/>`_.
  Note that support in Havana is only for V2 authentication.

User documentation
==================

If you do not intend to install it, but rather authenticate against a VOMS
service that is VOMS enabled, check the following link.

.. toctree::
   :maxdepth: 1

   usage

Deploying a VOMS Authentication in Keystone
===========================================

If you are a resource provider willing to deploy a VOMS-enabled keystone
service, check the following documentation:

.. toctree::
   :maxdepth: 1

   overview
   requirements
   installation
   configuration
   test
   troubleshooting
