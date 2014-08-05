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

VOMS module Configuration
=========================

VOMS configuration options
--------------------------

There are several new options in ``/etc/keystone/keystone.conf`` that are used
to configure the VOMS identity behaviour. The default values should be OK for
most installations, except the ``autocreate_users`` option. These optiones are
under the ``[voms]`` section::

    [voms]
    vomsdir_path = /etc/grid-security/vomsdir
    ca_path = /etc/grid-security/certificates
    voms_policy = /etc/keystone/voms.json
    vomsapi_lib = libvomsapi.so.1
    autocreate_users = False
    add_roles = False
    user_roles = _member_

* ``vomsdir_path``: Path storing the ``.lsc`` files.
* ``ca_path``: Path where the CAs and CRLs are stored.
* ``voms_policy``: JSON file containing the VO/tenant/role mapping.
* ``vomsapi_lib``: Path to the voms library to use.
* ``autocreate_users``: Whether a user should be autocreated if it does not exist.
* ``add_roles``: Whether roles should be added to users or not.
* ``user_roles``: list of role names to add to the users (if ``add_roles`` is ``True``).

Allowed VOs
-----------

For each allowed VO, you need a subdirectory in ``/etc/grid-security/vomsdir/``
that contains the ``.lsc`` files of all truted VOMS servers for the given VO.
The LSC files must be named as the fully qualified host name of the
VOMS server with an ``.lsc`` extension, and they contain:

* First line: subject DN of the VOMS server host certificate.
* Second line: subject DN of the CA that issued the VOMS server host certificate.

So, for example, for the `dteam VO <http://operations-portal.egi.eu/vo/view/voname/dteam>`_
the first should be::

    $ cat /etc/grid-security/vomsdir/dteam/voms.hellasgrid.gr.lsc
    /C=GR/O=HellasGrid/OU=hellasgrid.gr/CN=voms.hellasgrid.gr
    /C=GR/O=HellasGrid/OU=Certification Authorities/CN=HellasGrid CA 2006

The dteam VO has two VOMS servers (see link above) so another file for the
second server needs to be present as well::

    $ cat /etc/grid-security/vomsdir/dteam/voms2.hellasgrid.gr.lsc
    /C=GR/O=HellasGrid/OU=hellasgrid.gr/CN=voms2.hellasgrid.gr
    /C=GR/O=HellasGrid/OU=Certification Authorities/CN=HellasGrid CA 2006

For more details, please check the following page `How to configure VOMS LSC
files <http://italiangrid.github.io/voms/documentation/voms-clients-guide/3.0.3/#voms-trust>`_.
Note that you do not need to install the ``.pem`` certificate, just the ``.lsc``
file.

VO to local tenant mapping
~~~~~~~~~~~~~~~~~~~~~~~~~~

The VO and VO group mapping to the local tenants is made in the JSON
file ``/etc/keystone/voms.json``. It is based on the VO name and VOMS
proxy fqan::

  {
      "voname": {
          "tenant": "local_tenant"
      }
  }

For example for the dteam VO, it could be configured as::

  {
      "dteam": {
          "tenant": "dteam"
      },
      "/dteam/NGI_IBERGRID": {
          "tenant": "dteam_ibergrid"
      }
  }

If there are no matching FQANS but there is a VO name definition, the user will
authenticate, therefore, a user making the following request::

    {
        "auth": {
            "voms": "true",
            "tenantNane": "/dteam/NGI_IBERGRID",
        }
    }

against the following configuration::

    {
        "dteam": {
            "tenant": "dteam"
        }
    }

will be sucessfully authenticated, because no FQAN matched, but the VO did.
