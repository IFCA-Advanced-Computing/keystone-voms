# Running the tests

To run the Keystone-VOMS tests you simply need to run "tox".

However due to build problems with M2Crypto, it is recommended to install it
via your package manager. Moreover, OpenStack Keystone is not installable via
pip, you will need the required version as well, and then run "tox" with the
"--sitepackages" option:

    apt-get install python-m2crypto
    git clone https://github.com/openstack/keystone -b stable/liberty
    pip install keystone
    tox --sitepackages
