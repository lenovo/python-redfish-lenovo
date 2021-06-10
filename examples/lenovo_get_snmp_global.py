###
#
# Lenovo Redfish examples - Get SNMP global information
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


def lenovo_get_snmp_global(ip, login_account, login_password):
    """Get snmp global info
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns snmp global information when succeeded or error message when failed
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

    request_url = '/redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/SNMP'

    response_url = REDFISH_OBJ.get(request_url, None)
    if response_url.status == 404:
        result = {'ret': False, 'msg': 'Target server does not support Oem SNMP resource.'}
        REDFISH_OBJ.logout()
        return result

    if response_url.status != 200:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    snmpinfo = {}
    properties = ['SNMPv3Agent', 'SNMPTraps', 'CommunityNames']
    for property in properties:
        if property in response_url.dict:
            snmpinfo[property] = response_url.dict[property]
        else:
            snmpinfo[property] = None

    result['ret'] = True
    result['snmpinfo'] = snmpinfo

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

    # Get snmp global info and check result
    result = lenovo_get_snmp_global(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['snmpinfo'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

