###
#
# Lenovo Redfish examples - Get the network information
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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

# GET the Chassis resource
chassis_url = utils.get_chassis_url("/redfish/v1", REDFISH_OBJ)
response_chassis_url = REDFISH_OBJ.get(chassis_url, None)

# GET the NetworkAdapters resource from the Chassis resource
nic_adapter_url = response_chassis_url.dict["NetworkAdapters"]["@odata.id"]
response_nic_adapter_url = REDFISH_OBJ.get(nic_adapter_url, None)
nic_adapter_count = response_nic_adapter_url.dict["Members@odata.count"]

nic = 0
for nic in range (0, nic_adapter_count):
    nic_adapter_x_url = response_nic_adapter_url.dict["Members"][nic]["@odata.id"]
    response_nic_adapter_x_url = REDFISH_OBJ.get(nic_adapter_x_url, None)
    sys.stdout.write("Network Adapter # %s\n" % response_nic_adapter_x_url.dict["Id"])
    sys.stdout.write("  Name              : %s\n" % response_nic_adapter_x_url.dict["Name"])
    sys.stdout.write("  Firmware Version  : %s\n" % response_nic_adapter_x_url.dict["Controllers"][0]["FirmwarePackageVersion"])
    sys.stdout.write("  Adapter Health    : %s\n" % response_nic_adapter_x_url.dict["Status"]["Health"])
    sys.stdout.write("  NIC Devices       :\n")


    port = 0 
    # GET the NetworkDeviceFunction resources from each of the NetworkAdapter resources
    nic_dev_url = response_nic_adapter_x_url.dict["NetworkDeviceFunctions"]["@odata.id"]
    response_nic_dev_url = REDFISH_OBJ.get(nic_dev_url, None)
    nic_dev_count = response_nic_dev_url.dict["Members@odata.count"]
    for dev in range (0, nic_dev_count):
        nic_dev_x_url = response_nic_dev_url.dict["Members"][dev]["@odata.id"]
        response_nic_dev_x_url = REDFISH_OBJ.get(nic_dev_x_url, None)
        sys.stdout.write("  NIC Device # %s\n" % response_nic_dev_x_url.dict["Id"])
        sys.stdout.write("    Name                      : %s\n" % response_nic_dev_x_url.dict["Name"])
        sys.stdout.write("    Device Type               : %s\n" % response_nic_dev_x_url.dict["NetDevFuncType"])
        sys.stdout.write("    Device Enabled?           : %s\n" % response_nic_dev_x_url.dict["DeviceEnabled"])
        sys.stdout.write("    MAC Address               : %s\n" % response_nic_dev_x_url.dict["Ethernet"]["MACAddress"])
        sys.stdout.write("    MTU Size                  : %s\n" % response_nic_dev_x_url.dict["Ethernet"]["MTUSize"])
        sys.stdout.write("    Device Health             : %s\n" % response_nic_dev_x_url.dict["Status"]["Health"])
        sys.stdout.write("    Physical Ports            :\n")


        # GET the associated NetworkPort resource
        nic_port_x_url = response_nic_dev_x_url.dict["PhysicalPortAssignment"]["@odata.id"]
        response_nic_port_x_url = REDFISH_OBJ.get(nic_port_x_url, None)

        sys.stdout.write("    Physical Port # %s\n" % response_nic_port_x_url.dict["PhysicalPortNumber"])
        sys.stdout.write("    Physical Port Name        : %s\n" % response_nic_port_x_url.dict["Name"])
        sys.stdout.write("    LinkStatus                : %s\n" % response_nic_port_x_url.dict["LinkStatus"])
        sys.stdout.write("    Active Link Technology    : %s\n" % response_nic_port_x_url.dict["ActiveLinkTechnology"])
        sys.stdout.write("    Port Maximum MTU          : %s\n" % response_nic_port_x_url.dict["PortMaximumMTU"])
        sys.stdout.write("    Port Health               : %s\n" % response_nic_port_x_url.dict["Status"]["Health"])

        sys.stdout.write("\n")
    sys.stdout.write("\n")

# Logout of the current session
REDFISH_OBJ.logout()