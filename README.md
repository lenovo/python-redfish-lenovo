# Python-redfish-Lenovo


## Introduction

This project includes a set of sample Python scripts that utilize the Redfish API to manage Lenovo ThinkSystem servers.  The scripts use the [DMTF python-redfish-library](https://github.com/DMTF/python-redfish-library). For more information on the Redfish API, visit [DMTF's Redfish Developer Hub](http://redfish.dmtf.org/)

----------

## Installation

* To install the python-redfish-library, follow these two steps:

1. Get the code from [python-redfish-library](https://github.com/DMTF/python-redfish-library).

2. Run the following command in your terminal:
    
    `python setup.py install`

* To install configparser, run the following command in your terminal:

    `pip install configparser`

----------

## Software requirements


* Python-redfish-library needs to be installed.

----------

## Usage

A set of python examples are provided under the examples directory of this project.

* Common parameters configuration

You can use a configuration file to store common parameters such as the BMC IP address, user name, and password for the Lenovo PowerShell Redfish Scripts. Default configuration file is *config.ini*. 

You can also create your own configuration file and specify it using the *"--config"* option. The scripts will load *config.ini* automatically if no configuration file is specified in command line.

* Values viewing and setting

Run the relevant python script to show values in the HTTP GET operation. Here are two examples:

1. By running the following code, the terminal will show the current power state of the system (such as On or Off):
~~~~
cd examples
python get_power_state.py
~~~~
    
    
2. By running the following code, the terminal will show system reset types that are supported by your server, then passes one of the values (ForceOff) to force the server to shutdown:
~~~~
cd examples
python lenovo_get_reset_types.py
['On', 'Nmi', 'GracefulShutdown', 'GracefulRestart', 'ForceOn', 'ForceOff', 'ForceRestart']
Python lenovo_set_reset_types.py ForceOff
~~~~
    
    
-----------

## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D


---------------------

## Copyright and License

Copyright 2019 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
