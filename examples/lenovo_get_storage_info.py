###
#
# Lenovo Redfish examples - Get the storage information
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
login_host = "https://10.243.12.117"
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

# GET the Storage resources from the ComputerSystem resource
storage_url = response_system_url.dict["Storage"]["@odata.id"]
response_storage_url = REDFISH_OBJ.get(storage_url, None)
storage_count = response_storage_url.dict["Members@odata.count"]

storage = 0
for nic in range (0, storage_count):
    storage_x_url = response_storage_url.dict["Members"][nic]["@odata.id"]
    response_storage_x_url = REDFISH_OBJ.get(storage_x_url, None)
    sys.stdout.write("Storage # %s\n" % response_storage_x_url.dict["Id"])
    sys.stdout.write("  Name              : %s\n" % response_storage_x_url.dict["Name"])
    sys.stdout.write("  Storage Controllers       :\n")

    controller_count = response_storage_x_url.dict["StorageControllers@odata.count"]
    controller = 0 
    # GET the StorageControllers instances resources from each of the Storage resources
    for controller in range (0, controller_count):
        sys.stdout.write("  Controller # %s\n" % controller)
        sys.stdout.write("  Manufacturer               : %s\n" % response_storage_x_url.dict["StorageControllers"][controller]["Manufacturer"])
        sys.stdout.write("  Model                      : %s\n" % response_storage_x_url.dict["StorageControllers"][controller]["Model"])
        sys.stdout.write("  Serial Number              : %s\n" % response_storage_x_url.dict["StorageControllers"][controller]["SerialNumber"])
        sys.stdout.write("  Firmware Version           : %s\n" % response_storage_x_url.dict["StorageControllers"][controller]["FirmwareVersion"])
        sys.stdout.write("  Part Number                : %s\n" % response_storage_x_url.dict["StorageControllers"][controller]["PartNumber"])
        sys.stdout.write("  %s                      : %s\n" % 
                           (response_storage_x_url.dict["StorageControllers"][controller]["Identifiers"][0]["DurableNameFormat"], 
                           response_storage_x_url.dict["StorageControllers"][controller]["Identifiers"][0]["DurableName"]))


        sys.stdout.write("\n")
    sys.stdout.write("\n")

# Logout of the current session
REDFISH_OBJ.logout()