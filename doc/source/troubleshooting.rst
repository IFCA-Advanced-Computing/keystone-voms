Troubleshooting
===============

Apache complains about issuer of certificate
--------------------------------------------

You get something like::

  Certificate Verification: Error (20): unable to get local issuer certificate

You probably missed to set the ``OPENSSL_ALLOW_PROXY_CERTS`` variable on the
Apache environment

Error 14: Signature error
-------------------------

You have to check double check that the ``vomsdir_path`` and ``ca_path``
configuration options (that default to ``/etc/grid-security/vomsdir`` and
``/etc/grid-security/certificates`` respectively) point to the correct path.
Also ensure that the ``.lsc`` files have the right contents. and that the CLRs
are up to date.
