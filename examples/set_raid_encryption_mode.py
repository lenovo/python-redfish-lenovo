###
#
# Lenovo Redfish examples - Set raid encryption mode
#
# Copyright Notice:
#
# Copyright 2023 Lenovo Corporation
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
import traceback
import lenovo_utils as utils
import json


def set_raid_encryption_mode(ip, login_account, login_password, system_id, encryption_mode):
    """set raid encryption mode   
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params encryption_mode: Raid encryption mode
    :type encryption_mode: string
    :returns: returns set raid encryption mode result when succeeded or error message when failed
    """
    result = {}
    login_host = 'https://' + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result

    support_set_encryptionmode = False
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status != 200:
            error_message = utils.get_extended_error(response_system_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                system_url, response_system_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        
        if 'Storage' in response_system_url.dict:
            # Get the Storage resource url
            storage_url = response_system_url.dict['Storage']['@odata.id']
            response_storage_url = REDFISH_OBJ.get(storage_url, None)
            if response_storage_url.status == 200:
                storage_count = len(response_storage_url.dict["Members"])
                for i in range(0, storage_count):
                    storage_x_url = response_storage_url.dict["Members"][i]["@odata.id"]
                    response_storage_x_url = REDFISH_OBJ.get(storage_x_url, None)
                    if response_storage_x_url.status == 200:
                        if "EncryptionMode" in response_storage_x_url.dict:
                            support_set_encryptionmode = True
                            
                            if "@odata.etag" in response_storage_x_url.dict:
                                etag = response_storage_x_url.dict['@odata.etag']
                            else:
                                etag = "*"
                            headers = {"If-Match": etag}
                            parameter = {"EncryptionMode": encryption_mode}
                            response_set_encryptionmode = REDFISH_OBJ.patch(storage_x_url, body=parameter, headers=headers)
                            if response_set_encryptionmode.status in [200,204]:
                                    result = {'ret': True,
                                              'msg': "PATCH command successfully completed. Encryption mode has been set to %s." % (encryption_mode)}
                            else:
                                error_message = utils.get_extended_error(response_set_encryptionmode)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                                    storage_x_url, response_set_encryptionmode.status, error_message)}
                    else:
                        error_message = utils.get_extended_error(response_storage_x_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                            storage_x_url, response_storage_x_url.status, error_message)}
                        REDFISH_OBJ.logout()   
            else:
                error_message = utils.get_extended_error(response_storage_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                    storage_url, response_storage_url.status, error_message)}
                REDFISH_OBJ.logout()   

    if not support_set_encryptionmode:
        result = {'ret': False, 'msg': "Not support set raid EncryptionMode."}
    
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result

def add_helpmessage(parser):
    parser.add_argument('--encryption', type=str, required=True, choices=['Disabled', 'UseExternalKey'], help='Specify the raid encryption mode.Accepted settings are ["Disabled", "UseExternalKey"]. "UseExternalKey" can be set only when the external key management server is configured.')

def add_parameter():
    """Add set raid encryption mode parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['encryption'] = args.encryption
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    encryption_mode = parameter_info['encryption']
    
    # Get set raid encryption mode result and check result
    result = set_raid_encryption_mode(ip, login_account, login_password, system_id, encryption_mode)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
