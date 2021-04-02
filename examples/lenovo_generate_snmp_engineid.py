###
#
# Lenovo Redfish examples - Generate Lenovo SNMP engine id
#
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
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
import redfish
import traceback
import lenovo_utils as utils


def lenovo_generate_snmp_engineid(ip, login_account, login_password, system_id):
    """Generate SNMP engine id
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns generated SNMP engine id when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result

    sub_model = None
    serial_number = None
    host_name = None
    for i in range(len(system)):
        request_url = system[i]
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'SubModel' in response_url.dict:
            sub_model = response_url.dict['SubModel']
        if 'SerialNumber' in response_url.dict:
            serial_number = response_url.dict['SerialNumber']
        if 'HostName' in response_url.dict:
            host_name = response_url.dict['HostName']

    engine_id_string = ""
    if sub_model is not None and serial_number is not None:
        engine_id_string = "XCC-%s-%s" %(sub_model, serial_number)
    elif host_name is not None:
        engine_id_string = "%s" %(host_name)
    else:
        result = {'ret': False, 'msg': "Failed to get necessary information from ComputeSystem for SNMP engine id generating."}
        REDFISH_OBJ.logout()
        return result

    engine_id_hexstr = "80 00 1F 88 04"
    for char in engine_id_string:
        engine_id_hexstr = engine_id_hexstr + ' %2X' %(ord(char))
    result['ret'] = True
    result['data'] = engine_id_hexstr
    # Logout of the current session
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
    system_id = parameter_info['sysid']

    # Call function to generate and check result
    result = lenovo_generate_snmp_engineid(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['data'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

