# python-redfish-lenovo

Sample Python scripts for using the Redfish API on Lenovo servers

Description
----------

This project includes a set of sample Python scripts that utilize the Redfish API to manage Lenovo ThinkSystem servers.  The scripts use the DMTF python-redfish-library <https://github.com/DMTF/python-redfish-library>

For more information on the Redfish API, visit <http://redfish.dmtf.org/>

Installing
----------

* To install the python-redfish-library, get the code from <https://github.com/DMTF/python-redfish-library> , then:
    
    `python setup.py install`

* To install configparser:

    `pip install configparser`

    As configparser only support python3 from 5.0.0, if you are using python2.7, please specify version 4.0.2 while installing

    `pip install configparser==4.0.2`

* To install requests:

    `pip install requests`

Requirements
----------

* python-redfish-library need to be installed

Usage
----------
A set of python examples is provided under the examples directory of this project.

* Common parameters configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You can use a configuration file to store common parameters for the Lenovo PowerShell Redfish Scripts, 
such as the BMC IP address, user name, and password. Default configuration file is config.ini. 
You can create your own configuration file and specify it using the "--config" option. 
The scripts will load config.ini automatically if no configuration file is specified in command line.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* Using the python examples to get and set values

Simply run the python script to print out the values form the HTTP GET operation.

This example prints the current system power state (such as On or Off)

    cd examples
    python get_power_state.py
This example prints the system reset types that are supported by this server, then passes one of the values (ForceOff) to force the server to shutdown:

    cd examples
    python lenovo_get_reset_types.py
    ['On', 'Nmi', 'GracefulShutdown', 'GracefulRestart', 'ForceOn', 'ForceOff', 'ForceRestart']
    
    Python lenovo_set_reset_types.py ForceOff

Note: There are three scripts (raw_command_*.py) to support raw redfish get/patch/post requests. If existing scripts can't meet your requirement, please try them.

Contributing
----------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

Copyright and License
---------------------

Copyright 2019 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
