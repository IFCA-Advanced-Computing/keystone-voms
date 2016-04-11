..
      Copyright 2012 Spanish National Research Council

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

==============================
Openstack Keystone VOMS module
==============================

This module is intended to provide VOMS authentication to an
OpenStack Keystone. It is designed to be integrated as an external
authentication plugin, so that Keystone will preserve its original
features and users will still be able to authenticate using any of the
Keystone native mechanisms.

This documentation is based on a Keystone 9 (Mitaka) installation.

.. attention::
    If you are upgrading from any priorversion, check the
    :doc:`Upgrade nodes <upgrade>` before proceeding.

* Only V2 authentication is supported in Mitaka so far.
* If you are using the 2014.1 (Icehouse) version, please check the `Icehouse
  Documentation <http://keystone-voms.readthedocs.org/en/stable-icehouse/>`_.
  Note that support in Icehouse is only for V2 authentication.
* If you are using the 2014.2 (Juno) version, please check the `Juno
  Documentation <http://keystone-voms.readthedocs.org/en/stable-juno/>`_.
  Note that support in Icehouse is only for V2 authentication.
* If you are using the 2015.1 (Kilo) version, please check the `Kilo
  Documentation <http://keystone-voms.readthedocs.org/en/stable-kilo/>`_.
  Note that support in Kilo is only for V2 authentication.
* If you are using the 8.0.0 (Liberty) version, please check the `Liberty
  Documentation <http://keystone-voms.readthedocs.org/en/stable-liberty/>`_.
  Note that support in Liberty is only for V2 authentication.


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
service, check the following documentation.

.. attention::
    If you are upgrading from any priorversion, check the
    :doc:`Upgrade nodes <upgrade>` before proceeding.

.. note::
    Default configuration files vary by distribution. You might need to add
    these sections and options rather than modifying existing sections and
    options. Also, an ellipsis (...) in the configuration snippets indicates
    potential default configuration options that you should retain.


.. toctree::
   :maxdepth: 1

   overview
   requirements
   upgrade
   installation
   configuration
   test
   troubleshooting
