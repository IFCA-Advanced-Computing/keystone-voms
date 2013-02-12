Usage
=====

In order to get a token, you must post a JSON request in the body containing
the following::

    {
        "auth": {
            "voms": "true"
        }
    }

It is important to note here a difference between a VOMS backed keystone
installation and a vanilla Keystone.

In a normal keystone installation there are two types of possible request:
unscoped and scoped. The unscoped requests works without specifying a
``tenantName`` in the ``auth`` dictionary when making the request, whereas
a scoped request needs of such field. The request above is an uscoped request,
and the following is a scoped request::
    
    {
        "auth": {
            "voms": "true",
            "tenantNane": "dteam",
        }
    }

The particularity of the VOMS backend is that the user might not know to
which tenant he is mapped to (because the mapping is made internally), thus
the tenant name must be set to the VO name or the VOMS FQAN that he wants to
use to authenticate.
