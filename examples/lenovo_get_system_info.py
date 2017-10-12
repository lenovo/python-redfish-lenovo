###
#
# Lenovo Redfish examples - Get the System information
#
# Copyright Notice:
#
# Copyright 2017 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


import sys
import logging
import redfish
from redfish import redfish_logger
import lenovo_utils as utils

# Connect using the address, account name, and password
login_host = "https://10.243.13.101"
login_account = "USERID"
login_password = "PASSW0RD"


## Create a REDFISH object
REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, \
                          password=login_password, default_prefix='/redfish/v1')

# Login into the server and create a session
REDFISH_OBJ.login(auth="session")

# GET the ComputerSystem resource
system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
response_system_url = REDFISH_OBJ.get(system_url, None)

# Print out the system information
sys.stdout.write("\n")
sys.stdout.write("Host Name         : %s\n" % response_system_url.dict["HostName"])
sys.stdout.write("Model Number      : %s\n" % response_system_url.dict["Model"])
sys.stdout.write("Serial Number     : %s\n" % response_system_url.dict["SerialNumber"])
sys.stdout.write("Asset Tag         : %s\n" % response_system_url.dict["AssetTag"])
sys.stdout.write("System UUID       : %s\n" % response_system_url.dict["UUID"])
sys.stdout.write("Procesors Model   : %s\n" % response_system_url.dict["ProcessorSummary"]["Model"])
sys.stdout.write("Procesors Count   : %s\n" % response_system_url.dict["ProcessorSummary"]["Count"])
sys.stdout.write("Total Memory      : %s GB\n" % response_system_url.dict["MemorySummary"]["TotalSystemMemoryGiB"])
sys.stdout.write("BIOS Version      : %s\n" % response_system_url.dict["BiosVersion"])
sys.stdout.write("NIC MAC Addresses : \n")

# GET System EtherNetInterfaces resources
nics_url = response_system_url.dict["EthernetInterfaces"]["@odata.id"]
response_nics_url = REDFISH_OBJ.get(nics_url, None)
nic_count = response_nics_url.dict["Members@odata.count"]
x = 0
for x in range (0, nic_count):
    nic_x_url = response_nics_url.dict["Members"][x]["@odata.id"]
    response_nic_x_url = REDFISH_OBJ.get(nic_x_url, None)
    sys.stdout.write("   %s\n" % response_nic_x_url.dict["PermanentMACAddress"])

sys.stdout.write("\n")

# Logout of the current session
REDFISH_OBJ.logout()