###
#
# Lenovo Redfish examples - Update FW
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


def update_fw(ip, login_account, login_password, image_url, targets, protocol):
    """Set Bios attribute    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params image_url: User firmware driver url
    :type image_url: string
    :params targets: Targets list
    :type targets: list
    :params protocol: User update transfer Protocol
    :type protocol: string
    :returns: returns set bios attribute result when succeeded or error message when failed
    """
    # Connect using the address, account name, and password
    login_host = "https://" + ip 
    try:
        # Create a REDFISH object
        result = {}
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result


    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_update_service_url
    if response_base_url.status == 200:
        update_service_url = response_base_url.dict['UpdateService']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        return result

    response_update_service_url = REDFISH_OBJ.get(update_service_url, None)
    if response_update_service_url.status == 200:
        firmware_inventory_url = response_update_service_url.dict['Actions']['#UpdateService.SimpleUpdate']['target']
        parameter = {"ImageURI": imageurl, "Targets": targets, "TransferProtocol": protocol}
        response_firmware_inventory = REDFISH_OBJ.post(firmware_inventory_url, body=parameter)
        if response_firmware_inventory.status in [200, 202, 204]:
            result = {'ret': True, 'msg': "Update firmware successful"}
        else:
            result = {'ret': False, 'msg': "response firmware inventory Error code %s" % response_firmware_inventory.status}
    else:
        result = {'ret': False, 'msg': "response update service url Error code %s" % response_update_service_url.status}

    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add set bios attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--imageurl', type=str, help='Input the update firmware image url')
    argget.add_argument('--targets', type=str, help='Input the targets list')
    argget.add_argument('--protocol', type=str, help='Input the update firmware protocol')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    print(parameter_info)
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        imageurl = parameter_info['imageurl']
        targets = parameter_info['targets']
        protocol = parameter_info['protocol']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Update firmware result and check result
    result = update_fw(ip, login_account, login_password, imageurl, targets, protocol)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])