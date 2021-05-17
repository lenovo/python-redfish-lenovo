###
#
# Lenovo Redfish examples - configure ExternalKeyLifecycleManager(EKLM) key server
# SecureKeyLifecycleManager feature uses centralized EKLM server to provide keys that unlock storage hardware.
# To use this feature, below steps are needed:
#  - Ensure required license has been imported in BMC(XCC)
#  - Configure EKLM Server(s) in BMC(XCC)
#  - Install/import EKLM server certificate in BMC(XCC) which can be downloaded from EKLM server
#  - Generate EKLM client certificate CSR in BMC(XCC)
#  - Sign the CSR with the CA certificate in EKLM server
#  - Import the signed client certificate in BMC(XCC)
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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

import sys, os
import redfish
import json
import traceback
import lenovo_utils as utils


def lenovo_eklm_keyserver_config(ip, login_account, login_password, kmprotocol, kmhostname, kmport, kmgroup):
    """ Configure EKLM key server info
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params kmprotocol: eklm key management protocol
        :type kmprotocol: string
        :params kmhostname: eklm key server ip/hostname list
        :type kmhostname: list
        :params kmport: eklm key server port list
        :type kmport: list
        :params kmgroup: eklm device group name
        :type kmgroup: string
        :returns: returns successful result when succeeded or error message when failed
        """

    result = {}

    # Check parameter
    if len(kmhostname) > 4:
        result = {'ret': False, 'msg': "User can only specify up to 4 key servers."}
        return result
    if kmgroup is not None and kmgroup != '' and len(kmgroup) > 16:
        result = {'ret': False, 'msg': "User can only specify maximum length of 16 bytes for kmgroup."}
        return result

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get /redfish/v1
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    if response_base_url.status != 200:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            '/redfish/v1', response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get /redfish/v1/Managers
    managers_url = response_base_url.dict['Managers']['@odata.id']
    response_managers_url = REDFISH_OBJ.get(managers_url, None)
    if response_managers_url.status != 200:
        error_message = utils.get_extended_error(response_managers_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            managers_url, response_managers_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Access /redfish/v1/Managers/1 to get SecureKeyLifecycleService url
    eklm_url = None
    for request in response_managers_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        if 'SecureKeyLifecycleService' in str(response_url.dict):
            eklm_url = response_url.dict['Oem']['Lenovo']['SecureKeyLifecycleService']['@odata.id']
            break

    # Return here when EKLM feature is not supported
    if eklm_url is None:
        result = {'ret': False, 'msg': 'ExternalKeyLifecycleManager(EKLM) is not supported.'}
        REDFISH_OBJ.logout()
        return result

    # Check whether SKLM is supported
    if kmprotocol == 'SKLM':
        request_url = eklm_url
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        if 'Protocol@Redfish.AllowableValues' in response_url.dict and 'SKLM' not in response_url.dict['Protocol@Redfish.AllowableValues']:
            result = {'ret': False, 'msg': 'SKLM protocol is not supported(extra license needed), only KMIP is supported on target server.'}
            REDFISH_OBJ.logout()
            return result

    # Patch configuration via /redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService
    requestbody = {'KeyRepoServers':[]}
    for index in range(4):
        keyserver = {}
        keyserver['HostName'] = kmhostname[index] if len(kmhostname)>index else ''
        keyserver['Port'] = kmport[index] if len(kmport)>index else 5696
        requestbody['KeyRepoServers'].append(keyserver)
    if kmgroup is not None and kmgroup != '':
        requestbody['DeviceGroup'] = kmgroup
    requestbody['Protocol'] = kmprotocol  #Value for Protocol can be SKLM or KMIP
    headers = {'If-Match': '*'}
    request_url = eklm_url
    response_url = REDFISH_OBJ.patch(request_url, body=requestbody, headers=headers)
    if response_url.status in [200, 204]:
        result = {'ret': True, 'msg': "Configure EKLM key server successfully"}
        REDFISH_OBJ.logout()
        return result
    else:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result


def add_helpmessage(parser):
    parser.add_argument('--kmprotocol', type=str, default="KMIP", required=False, choices=["KMIP", "SKLM"],
                         help='Specify the key management protocol. Support:["KMIP", "SKLM"]')
    parser.add_argument('--kmhostname', nargs="*", type=str, required=True,
                         help='Key management server hostname or IP address. Up to 4 servers are supported.')
    parser.add_argument('--kmport', nargs="*", type=int, default=[5696,5696,5696], required=False,
                         help='The corresponding port for key management server. Default port is 5696.')
    parser.add_argument('--kmgroup', type=str, required=False,
                         help='A device group allows users to manage the keys for drives on multiple servers as a group. This field is optional.')


def add_parameter():
    """Add parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["kmprotocol"] = args.kmprotocol
    parameter_info["kmhostname"] = args.kmhostname
    parameter_info["kmport"] = args.kmport
    parameter_info["kmgroup"] = args.kmgroup
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    kmprotocol = parameter_info["kmprotocol"]
    kmhostname = parameter_info["kmhostname"]
    kmport = parameter_info["kmport"]
    kmgroup = parameter_info["kmgroup"]

    # Configure EKLM key server info and check result
    result = lenovo_eklm_keyserver_config(ip, login_account, login_password, kmprotocol, kmhostname, kmport, kmgroup)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

