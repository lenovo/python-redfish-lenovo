###
#
# Lenovo Redfish examples - Get the current BMC User Accounts
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

# GET the Accounts resource
response_base_url = REDFISH_OBJ.get("/redfish/v1", None)

account_service_url = response_base_url.dict["AccountService"]["@odata.id"]
response_account_service_url = REDFISH_OBJ.get(account_service_url, None)

accounts_url = response_account_service_url.dict["Accounts"]["@odata.id"]
accounts_url_response = REDFISH_OBJ.get(accounts_url, None)

# Loop through Accounts and print info
account_count = accounts_url_response.dict["Members@odata.count"]
x = 0
for x in range (0, account_count):
    account_x_url = accounts_url_response.dict["Members"][x]["@odata.id"]
    response_account_x_url = REDFISH_OBJ.get(account_x_url, None)

    # Print out account information if account is valid (UserName not blank)
    if response_account_x_url.dict["UserName"]:
        # Get account privileges
        accounts_role_url = response_account_x_url.dict["Links"]["Role"]["@odata.id"]
        response_accounts_role_url = REDFISH_OBJ.get(accounts_role_url, None)

        sys.stdout.write("Account Name        :  %s\n" % response_account_x_url.dict["Name"])
        sys.stdout.write("User Name           :  %s\n" % response_account_x_url.dict["UserName"])
        sys.stdout.write("Enabled             :  %s\n" % response_account_x_url.dict["Enabled"])
        sys.stdout.write("Locked              :  %s\n" % response_account_x_url.dict["Locked"])
        sys.stdout.write("Assigned Priveleges :  %s\n" % response_accounts_role_url.dict["AssignedPrivileges"])
        sys.stdout.write("OEM Privileges      :  %s\n" % response_accounts_role_url.dict["OemPrivileges"])
        sys.stdout.write("\n")


# Logout of the current session
REDFISH_OBJ.logout()