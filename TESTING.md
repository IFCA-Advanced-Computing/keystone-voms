# Running the tests

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

    cp /path/to/the/keystone/voms/module/tests/* /tmp/keystone/keystone/tests
    cd /tmp/keystone/
    ./run_tests.sh

You should get no errors at this point.
