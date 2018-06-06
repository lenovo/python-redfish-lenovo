###
#
# Lenovo Redfish examples - Clear_System_log
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
import redfish
import lenovo_utils as utils


def connect_redfish_client(login_host, login_account, login_password):
    # Connect using the address, account name, and password

    ## Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    REDFISH_OBJ.login(auth="session")
    return REDFISH_OBJ


def get_members_info(REDFISH_OBJ):
    # GET the ComputerSystem resource
    system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    response_system_url = REDFISH_OBJ.get(system_url, None)
    if response_system_url.status == 200:
        # Get the ComputerProcessors resource
        LogServices_url = response_system_url.dict['LogServices']['@odata.id']
        # print(LogServices_url)
    else:
        print("response_system_url Error code %s" % response_system_url.status)
        return
    response_logservices_url = REDFISH_OBJ.get(LogServices_url, None)
    if response_logservices_url.status == 200:
        members = response_logservices_url.dict['Members']

    else:
        print("response_logservices_url Error code %s" % response_logservices_url.status)
        return
    for member in members:
        log_url = member['@odata.id']
        response_log_url = REDFISH_OBJ.get(log_url, None)
        if "Actions" in response_log_url.dict:
            if "#LogService.ClearLog" in response_log_url.dict["Actions"]:
                clear_log_url = response_log_url.dict["Actions"]["#LogService.ClearLog"]["target"]
                response_clear_log = REDFISH_OBJ.post(clear_log_url, None)
                # print(response_clear_log.status, response_clear_log.dict)
                if response_clear_log.status == 200:
                    sys.stdout.write("Clear log successfully")

    REDFISH_OBJ.logout()


if __name__ == '__main__':
    login_host = 'https://10.245.39.185'
    login_account = 'USERID'
    login_password = 'PASSW0RD'
    # login_host = 'https://' + sys.argv[1]
    # login_account = sys.argv[2]
    # login_password = sys.argv[3]
    REDFISH_OBJ = connect_redfish_client(login_host, login_account, login_password)
    get_members_info(REDFISH_OBJ)