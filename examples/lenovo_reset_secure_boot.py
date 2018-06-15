###
#
# Lenovo Redfish examples - Reset secure boot
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
import redfish
import json
import lenovo_utils as utils


def reset_secure_boot(ip, login_account, login_password, system_id, reset_keys_type):
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        # Get the ComputerEthernetInterfaces resource
        if response_system_url.status == 200:
            secure_boot_url = response_system_url.dict['SecureBoot']['@odata.id']
        else:
            print("response_system_url Error code %s" % response_system_url.status)
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        response_secure_boot_url = REDFISH_OBJ.get(secure_boot_url, None)
        if response_secure_boot_url.status == 200:
            reset_action_url = response_secure_boot_url.dict["Actions"]["#SecureBoot.ResetKeys"]["target"]
            body = {"ResetKeysType": reset_keys_type}
            response_reset_url = REDFISH_OBJ.post(reset_action_url, body=body)
            if response_reset_url.status == 200:
                result = {'ret': True, 'msg': "clear all keys successful"}
            else:
                result = {'ret': False, 'msg': " response reset url Error code %s" % response_reset_url.status}
                REDFISH_OBJ.logout()
                return result
        else:
            result = {'ret': False, 'msg': " response secure boot url Error code %s" % response_secure_boot_url.status}

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
        # "DeleteAllKeys" or "DeletePK" or "ResetAllKeysToDefault"
        reset_keys_type = sys.argv[5]
    except IndexError:
        system_id = None
        # "DeleteAllKeys" or "DeletePK" or "ResetAllKeysToDefault"
        reset_keys_type = sys.argv[4]
    result = reset_secure_boot(ip, login_account, login_password, system_id, reset_keys_type)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])