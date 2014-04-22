# Running the tests

First, get the keystone code, and create the virtualenv::

    git clone https://github.com/openstack/keystone/ -b stable/icehouse /tmp/keystone/
    virtualenv /tmp/keystone/.venv/
    source /tmp/keystone/.venv/bin/activate
    pip install -r /tmp/keystone/requirements.txt
    pip install -r /tmp/keystone/test-requirements.txt


Then, from this repository, install the dependencies and the VOMS module into the
virtualenv created in the step above::

    cd keystone_voms
    pip install -r requirements.txt
    sudo apt-get install libvomsapi1
    pip install .

Copy the tests and run them::

    cp tests/* /tmp/keystone/keystone/tests
    cd /tmp/keystone/
    nosetests keystone.tests.test_middleware_voms_authn

You should get no errors at this point.
