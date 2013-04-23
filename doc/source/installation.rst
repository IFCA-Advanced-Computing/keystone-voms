============
Installation
============

This module assumes that keystone is at least running the Grizzly version, since
it needs some latest additions that are not available in any prior release. You
can fetch the ubuntu packages and install it from the `Grizzly Trunk testing PPA
<https://launchpad.net/~openstack-ubuntu-testing/+archive/grizzly-trunk-testing>`_.

Install the Keystone VOMS module
--------------------------------

Install from the Python Package Index
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can install it directly from PyPI::

    pip install keystone_voms

Install from PPA
~~~~~~~~~~~~~~~~

You can install the latest version from a private PPA::

    sudo add-apt-repository ppa:aloga/keystone-voms
    sudo aptitude update
    sudo aptitude install python-keystone-voms

Install from source
~~~~~~~~~~~~~~~~~~~

With a running Grizzly installation, simply install this egg. In the upper-level
directory run ``python setup.py install``::

    git clone git://github.com/IFCA/keystone-voms.git
    cd keystone-voms
    sudo python setup.py install

Enable the Keystone VOMS module
-------------------------------

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. Add the VOMS filter to your
configuration file ``/etc/keystone/keystone.conf`` ::

    [filter:voms]
    use = egg:keystone_voms#voms_filter

Then add this filter to the ``public_api`` pipeline::

    [pipeline:public_api]
    pipeline = sizelimit stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body voms debug ec2_extension user_crud_extension public_service

Note that you may have a different pipeline. You don't need to replace your
pipeline with the above, but just add the ``voms`` filter after the
``json_body`` entry.
