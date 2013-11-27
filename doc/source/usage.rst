.. _usage:

VOMS authentication client plugin
=================================

In order to facilitate the usage of the VOMS authentication with an
OpenStack installation an `authentication plugin for the nova client
<https://github.com/IFCA/voms-auth-system-openstack>`_ has been created. Please
follow its `instructions
<https://github.com/IFCA/voms-auth-system-openstack/blob/stable/havana/README.rst>`_
in order to use it.

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
