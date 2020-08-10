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
import lenovo_utils as utils

def get_fw_inventory(ip, login_account, login_password):
    """Get BMC inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns firmware inventory when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check if the username, password, IP is correct."}
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
                    for property in ['Version', 'SoftwareId', 'Description', 'Status']:
                        if property in response_firmware_version.dict:
                            fw[property] = response_firmware_version.dict[property]
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

    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info



if __name__ == '__main__':
     # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get firmware inventory and check result
    result = get_fw_inventory(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['fw_version_detail'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
