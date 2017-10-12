###
#
# Lenovo Redfish examples - Get the BMC information
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

# GET the Manager resource
manager_url = response_system_url.dict["Links"]["ManagedBy"][0]["@odata.id"]
response_manager_url = REDFISH_OBJ.get(manager_url, None)

# Get Manager NetworkProtocol resource
network_protocol_url = response_manager_url.dict["NetworkProtocol"]["@odata.id"]
response_network_protocol_url = REDFISH_OBJ.get(network_protocol_url, None)

# Print out the BMC information
sys.stdout.write("\n")
sys.stdout.write("BMC FW Version        : %s\n" % response_manager_url.dict["FirmwareVersion"])
sys.stdout.write("BMC Model             : %s\n" % response_manager_url.dict["Model"])
sys.stdout.write("BMC Date/Time         : %s\n" % response_manager_url.dict["DateTime"])
sys.stdout.write("BMC FQDN              : %s \n" % response_network_protocol_url.dict["FQDN"])
sys.stdout.write("BMC HostName          : %s \n" % response_network_protocol_url.dict["HostName"])
sys.stdout.write("BMC Port Numbers      : \n")
sys.stdout.write("   HTTP          : %s\n" % response_network_protocol_url.dict["HTTP"]["Port"])
sys.stdout.write("   HTTPs         : %s\n" % response_network_protocol_url.dict["HTTPS"]["Port"])
sys.stdout.write("   KVMIP         : %s\n" % response_network_protocol_url.dict["KVMIP"]["Port"])
sys.stdout.write("   IPMI          : %s\n" % response_network_protocol_url.dict["IPMI"]["Port"])
sys.stdout.write("   SSDP          : %s\n" % response_network_protocol_url.dict["SSDP"]["Port"])
sys.stdout.write("   SSH           : %s\n" % response_network_protocol_url.dict["SSH"]["Port"])
sys.stdout.write("   SNMP          : %s\n" % response_network_protocol_url.dict["SNMP"]["Port"])
sys.stdout.write("   Virtual Media : %s\n" % response_network_protocol_url.dict["VirtualMedia"]["Port"])



# GET Mangaer EtherNetInterfaces resources
nics_url = response_manager_url.dict["EthernetInterfaces"]["@odata.id"]
response_nics_url = REDFISH_OBJ.get(nics_url, None)
nic_count = response_nics_url.dict["Members@odata.count"]
x = 0
sys.stdout.write("BMC NIC MAC Addresses : \n")
for x in range (0, 1):  #for now
    nic_x_url = response_nics_url.dict["Members"][x]["@odata.id"]
    response_nic_x_url = REDFISH_OBJ.get(nic_x_url, None)
    sys.stdout.write("   %s\n" % response_nic_x_url.dict["PermanentMACAddress"])


# GET Manager SerialInterfaces resources
sys.stdout.write("BMC Serial Interfaces : \n")
serial_url = response_manager_url.dict["SerialInterfaces"]["@odata.id"]
response_serial_url = REDFISH_OBJ.get(serial_url, None)
serial_count = response_serial_url.dict["Members@odata.count"]
x = 0
for x in range (0, serial_count):
    serial_x_url = response_serial_url.dict["Members"][x]["@odata.id"]
    response_serial_x_url = REDFISH_OBJ.get(serial_x_url, None)
    sys.stdout.write("   Id           : %s\n" % response_serial_x_url.dict["Id"])
    sys.stdout.write("   Bit Rate     : %s\n" % response_serial_x_url.dict["BitRate"])
    sys.stdout.write("   Parity       : %s\n" % response_serial_x_url.dict["Parity"])
    sys.stdout.write("   Stop Bits    : %s\n" % response_serial_x_url.dict["StopBits"])
    sys.stdout.write("   Flow Control : %s\n" % response_serial_x_url.dict["FlowControl"])


sys.stdout.write("\n")

# Logout of the current session
REDFISH_OBJ.logout()