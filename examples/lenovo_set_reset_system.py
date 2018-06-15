###
#
# Lenovo Redfish examples - Reset System with the selected Reset Type
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
import json
import logging
import redfish
from redfish import redfish_logger
import lenovo_utils as utils


def set_reset_system(ip, login_account, login_password, system_id, reset_type):
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        sys.stdout.write("Please check the username, password, IP is correct\n")
        sys.exit(1)
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1",system_id,  REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        # GET the ComputerSystem resource
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # Find the Reset Action target URL
            target_url = response_system_url.dict["Actions"]["#ComputerSystem.Reset"]["target"]
            # Prepare POST body
            post_body = {"ResetType": ""}
            post_body["ResetType"] = reset_type
            # POST Reset Action
            post_response = REDFISH_OBJ.post(target_url, body=post_body)

            # If Response return 200/OK, return successful , else print the response Extended Error message
            if post_response.status == 200:
                result = {'ret': True, 'msg': "reset system %s successful" % reset_type}
            else:
                message = utils.get_extended_error(post_response)
                result = {'ret': False, 'msg': "Error message is %s" % message}
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    try:
        system_id = sys.argv[4]
        # "On", "Nmi", "GracefulShutdown", "GracefulRestart", "ForceOn", "ForceOff", "ForceRestart"
        reset_type = sys.argv[5]
    except IndexError:
        system_id = None
        # "On", "Nmi", "GracefulShutdown", "GracefulRestart", "ForceOn", "ForceOff", "ForceRestart"
        reset_type = sys.argv[4]
    result = set_reset_system(ip, login_account, login_password,system_id, reset_type)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
