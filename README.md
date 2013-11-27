Keystone VOMS authentication module
===================================

This module is intended to provide VOMS authentication to a Grizzzly OpenStack Keystone.

The documentation can be found in the following URL: https://keystone-voms.readthedocs.org/en/latest/

Running the tests
=================

First, get the keystone code, and generate the virtualenv by running the tests::

    git clone https://github.com/openstack/keystone/ -b stable/havana /tmp/keystone/
    cd /tmp/keystone/
    virtualenv --system-site-packages .venv/
    ./run_tests.sh -u

Then, activate the virtualenv and install the VOMS module into it::

    source /tmp/keystone/.venv/bin/activate
    cd /path/to/the/keystone/voms/module
    python setup.py install

Copy the tests and run them::

    cp /path/to/the/keystone/voms/module/tests/* /tmp/keystone/tests
    cd /tmp/keystone/
    ./run_tests.sh test_middleware_voms_authn
