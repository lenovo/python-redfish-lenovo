###
#
# Lenovo Redfish examples - Get secure boot status
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
import lenovo_utils as utils
import json


def get_secure_boot_status(ip, login_account, login_password):
    result = {}
    login_host = "https://" + ip
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')
    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    # GET the ComputerSystem resource
    secure_details = []
    system = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        # Get the ComputerEthernetInterfaces resource
        if response_system_url.status == 200:
            secure_boot_url = response_system_url.dict['SecureBoot']['@odata.id']
            
        else:
            print("response_system_url Error code %s" % response_system_url.status)
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            return result
        response_secure_boot_url = REDFISH_OBJ.get(secure_boot_url, None)
        if response_secure_boot_url.status == 200:
            secure = {}
            secure_boot_enable = response_secure_boot_url.dict["SecureBootEnable"]
            secure_boot_mode = response_secure_boot_url.dict["SecureBootMode"]
            secure['SecureBootEnable'] = secure_boot_enable
            secure['SecureBootMode'] = secure_boot_mode
            secure_details.append(secure)
        else:
            result = {'ret': False, 'msg': " response_secure_boot_url Error code %s" %  response_secure_boot_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = secure_details
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    result = get_secure_boot_status(ip, login_account, login_password)
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])