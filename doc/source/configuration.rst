Configuration
=============

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
files <https://twiki.cern.ch/twiki/bin/view/LCG/VOMSLSCfileConfiguration#LSC_file_configuration_by_other>`_.

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


VOMS configuration options
--------------------------

There are several new options in ``/etc/keystone/keystone.conf`` that are used
to configure the VOMS identity behaviour. The default values should be OK for
most installations. These are under the ``[voms]`` section::

    [voms]
    vomsdir_path = /etc/grid-security/vomsdir
    ca_path = /etc/grid-security/certificates
    voms_policy = /etc/keystone/voms.json
    vomsapi_lib = libvomsapi.so.1
    autocreate_users = False

* ``vomsdir_path``: Path storing the ``.lsc`` files.
* ``ca_path``: Path where the CAs and CRLs are stored.
* ``voms_policy``: JSON file containing the VO/tenant/role mapping.
* ``vomsapi_lib``: Path to the voms library to use.
* ``autocreate_users``: Whether we should create the users for the trusted VOs on the fly.




