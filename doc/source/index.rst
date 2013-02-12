==============================
Openstack Keystone VOMS module
==============================

VOMS Introduction
=================

The VOMS service can issue x509 proxies based on RFC 3820
(https://www.ietf.org/rfc/rfc3820.txt) by using the ``-rfc`` option in
the comandline. Instead of using plain x509 certificates this proxy can
be used to authenticate against a properly configured Keystone server.

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
