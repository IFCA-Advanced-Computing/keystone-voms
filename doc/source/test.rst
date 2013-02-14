Test it!
========

Once you have everything configured you can test it requesting a token using
a valid VOMS proxy::

  $ voms-proxy-init -voms <VOMS> -rfc
  $ curl --insecure --cert $X509_USER_PROXY  -d \
   '{"auth":{"voms": true}}' -H "Content-type: \
    application/json" https://<keystone_host>/v2.0/tokens
