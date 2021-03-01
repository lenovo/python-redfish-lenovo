###
#
# Lenovo Redfish examples - Enable secure boot
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


def enable_secure_boot(ip, login_account, login_password, system_id):
    """Enable secure boot    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns enable secure boot result when succeeded or error message when failed
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
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
        if response_system_url.status != 200:
            error_message = utils.get_extended_error(response_system_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                system_url, response_system_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'SecureBoot' in response_system_url.dict:
            # Toggle Remote Physical Presence Asset if Oem/Lenovo/TPMSettings/AssertRPP exist
            if 'Oem' in response_system_url.dict and 'Lenovo' in response_system_url.dict['Oem']:
                if 'TPMSettings' in response_system_url.dict['Oem']['Lenovo'] and 'AssertRPP' in response_system_url.dict['Oem']['Lenovo']['TPMSettings']:
                    if response_system_url.dict['Oem']['Lenovo']['TPMSettings']['AssertRPP'] != True:
                        parameter = {"Oem": {"Lenovo": {"TPMSettings": {"AssertRPP": True}}}}
                        headers = {"If-Match": response_system_url.dict['@odata.etag']}
                        response_patch = REDFISH_OBJ.patch(system_url, body=parameter, headers=headers)
                        if response_patch.status not in [200,204]:
                            error_message = utils.get_extended_error(response_patch)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                                system_url, response_patch.status, error_message)}

            # Get the SecureBoot resource url
            secureboot_url = response_system_url.dict['SecureBoot']['@odata.id']
            # get etag to set If-Match precondition
            response_secureboot_url = REDFISH_OBJ.get(secureboot_url, None)
            if response_secureboot_url.status != 200:
                error_message = utils.get_extended_error(response_secureboot_url)
                result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                    secureboot_url, response_secureboot_url.status, error_message)}
                REDFISH_OBJ.logout()
                return result
            if "@odata.etag" in response_secureboot_url.dict:
                etag = response_secureboot_url.dict['@odata.etag']
            else:
                etag = "*"
            headers = {"If-Match": etag}

            # perform patch to enable secure boot
            secure_boot_enable = True
            parameter = {"SecureBootEnable": secure_boot_enable}
            response_secureboot = REDFISH_OBJ.patch(secureboot_url, body=parameter, headers=headers)
            if response_secureboot.status in [200,204]:
                result = {'ret': True,
                          'msg': "PATCH command successfully completed. SecureBootEnable has been set to True."}
            else:
                error_message = utils.get_extended_error(response_secureboot)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                    secureboot_url, response_secureboot.status, error_message)}
            try:
                REDFISH_OBJ.logout()
            except:
                pass
            return result

    result = {'ret': False, 'msg': "Not support SecureBoot"}
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get enable secure boot result and check result
    result = enable_secure_boot(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
