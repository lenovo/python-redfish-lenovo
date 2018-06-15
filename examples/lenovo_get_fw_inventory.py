###
#
# Lenovo Redfish examples - Get FW inventory
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


def get_fw_inventory(ip, login_account, login_password):
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    fw_version = []
    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_update_service_url
    if response_base_url.status == 200:
        update_service_url = response_base_url.dict['UpdateService']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result

    response_update_service_url = REDFISH_OBJ.get(update_service_url, None)
    if response_update_service_url.status == 200:
        firmware_inventory_url = response_update_service_url.dict['FirmwareInventory']['@odata.id']
        response_firmware_url = REDFISH_OBJ.get(firmware_inventory_url, None)
        if response_firmware_url.status == 200:
            for firmware_url in response_firmware_url.dict["Members"]:
                firmware_version_url = firmware_url['@odata.id']
                firmware_list = firmware_version_url.split("/")
                response_firmware_version = REDFISH_OBJ.get(firmware_version_url, None)
                if response_firmware_version.status == 200:
                    fw = {}
                    Version = response_firmware_version.dict['Version']
                    SoftwareId = response_firmware_version.dict['SoftwareId']
                    Description = response_firmware_version.dict['Description']
                    State = response_firmware_version.dict['Status']['State']
                    fw['Version'] = Version
                    fw['SoftwareId'] = SoftwareId
                    fw['Description'] = Description
                    fw['State'] = State
                    fw = {firmware_list[-1]: fw}
                    fw_version.append(fw)
                else:
                    result = {'ret': False,
                              'msg': "response firmware version Error code %s" % response_firmware_version.status}
                    REDFISH_OBJ.logout()
                    return result
        else:
            result = {'ret': False, 'msg': "response firmware url Error code %s" % response_firmware_url.status}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "response update service_url Error code %s" % response_update_service_url.status}
        REDFISH_OBJ.logout()
        return result

    result['ret'] = True
    result['fw_version_detail'] = fw_version

    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    result = get_fw_inventory(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['fw_version_detail'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
