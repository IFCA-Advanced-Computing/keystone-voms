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

.. _usage:

VOMS authentication client plugin
=================================

In order to facilitate the usage of the VOMS authentication with an
OpenStack installation there is an `authentication plugin for the
keystoneauth library <https://github.com/enolfc/openstack-voms-auth-type>`_
has been created. This plugin can be used with the `python-openstackclient
<http://docs.openstack.org/developer/python-openstackclient/>`_. Follow
the `instructions <https://github.com/enolfc/openstack-voms-auth-type>`_ to
use it.

A `(deprecated) plugin for the Nova client
<https://github.com/IFCA/voms-auth-system-openstack/>`_ is also available for
older installations.

Manual Usage
============

In order to get a token, you must post a JSON request in the body containing
the following::

    {
        "auth": {
            "voms": "true"
        }
    }

In order to get a scoped token, use the following JSON document::

    {
        "auth": {
            "voms": "true",
            "tenantNane": "TenantForTheVo",
        }
    }
