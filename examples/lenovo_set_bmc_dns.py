###
#
# Lenovo Redfish examples - Set manager dns
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


import sys
import json
import redfish
import traceback
import lenovo_utils as utils


def lenovo_set_bmc_dns(ip, login_account, login_password, enabled, dnsserver):
    """Set manager ip
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params enabled: DNS enabled or not for BMC nic
    :type enabled: string
    :params dnsserver: DNS servers by user specified
    :type dnsserver: list
    :returns: returns set result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        manager_url = response_base_url.dict['Managers']['@odata.id']
    else:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '/redfish/v1' response error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get the manager url response resource
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % ( 
            manager_url, response_manager_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    for request in response_manager_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'NetworkProtocol' not in  response_url.dict:
            continue

        request_url = request['@odata.id'] + '/NetworkProtocol/Oem/Lenovo/DNS'
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            result = {'ret': False, 'msg': 'Not support Lenovo DNS setting'}
            REDFISH_OBJ.logout()
            return result

        payload = {'DNSEnable': True if enabled == '1' else False}
        if enabled == '1' and dnsserver is None:
            result = {'ret': False, 'msg': 'Please specify the DNS servers'}
            REDFISH_OBJ.logout()
            return result
        if dnsserver is not None:
            len_dns = len(dnsserver)
            if len_dns > 3:
                result = {'ret': False, 'msg': 'User can only specify the name of up to 3 DNS servers'}
                REDFISH_OBJ.logout()
                return result
            if 'Actions' in response_url.dict:
                if '#DNS.Reset' in response_url.dict['Actions']:
                    # SR635 / SR655
                    payload.clear()
                    payload = {'DNSStatus': 'enable' if enabled == '1' else 'disable'}
                    payload['DNSDHCP'] = 'Static'
                    payload['DNSIndex'] = 'none'
                    payload['IPPriority'] = 'none'
                    for index in range(len(dnsserver)):
                        payload['DNSServerIP%s' %(index+1)] = dnsserver[index]
            else:
                # XCC
                payload['PreferredAddresstype'] = 'IPv4'  #IPv6 address type is supported too
                for index in range(len(dnsserver)):
                    payload['IPv4Address%s' %(index+1)] = dnsserver[index]  #Update IPv4Address to IPv6Address here if using IPv6

        # perform set via patch
        headers = {"If-Match": "*"}
        response_url = REDFISH_OBJ.patch(request_url, body=payload, headers=headers)
        if response_url.status in [200,204]:
            if 'Actions' in response_url.dict:
                if '#DNS.Reset' in response_url.dict['Actions']:
                    # For SR635 / SR655 products, need reset the DNS
                    reset_url = request_url + '/' + 'Actions' + '/' + 'DNS.reset'
                    body = {"ResetType": "restart"}
                    response_reset_url = REDFISH_OBJ.post(reset_url, body=body)
                    if response_reset_url.status == 200:
                        result = {'ret': True, 'msg': "Set BMC DNS config successfully.\n"
                                                      "Start to reset the DNS, may take about 1 minute..."}
                    else:
                        error_message = utils.get_extended_error(reset_url)
                        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                            reset_url, response_reset_url.status, error_message)}
            else:
                # XCC
                result = {'ret': True, 'msg': "Set BMC DNS config successfully"}

        else:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                      request_url, response_url.status, error_message)}

        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def add_helpmessage(argget):
    argget.add_argument('--enabled', type=str, choices = ["0", "1"], required=True, default="1",
                        help='Indicates if DNS is enabled or disabled for the bmc nic. (0:false, 1:true)')
    argget.add_argument('--dnsserver',  nargs="*", type=str, required=False, help='Specify the names of DNS servers, up to 3 DNS servers can be used.')


def add_parameter():
    """Add set manager dns server parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["enabled"] = args.enabled
    parameter_info["dnsserver"] = args.dnsserver
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # set manager dns and check result
    result = lenovo_set_bmc_dns(ip, login_account, login_password, parameter_info["enabled"],
                            parameter_info["dnsserver"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

