###
#
# Lenovo Redfish examples - Set the System Boot Once target
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

# GET the ComputerSystem resource URL
system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)

# Prepare PATCH Body to set Boot once to the user specified target
patch_body = {"Boot": {"BootSourceOverrideEnabled": "", "BootSourceOverrideTarget": "" }}
patch_body["Boot"]["BootSourceOverrideEnabled"] = "Once"
patch_body["Boot"]["BootSourceOverrideTarget"] = sys.argv[1]

patch_response = REDFISH_OBJ.patch(system_url, body=patch_body)

# If Response does not return 200/OK, print the response Extended Error message
if patch_response.status != 200:
    message = utils.get_extended_error(patch_response)
    print ("Error message is %s" % message)

# Logout of the current session
REDFISH_OBJ.logout()
