###
#
# Lenovo Redfish examples - Set manager ip
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
import lenovo_utils as utils


def set_bmc_ip(ip, login_account, login_password, dhcp_enabled, static_ip, static_gateway, static_mask):
    """Set manager ip
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params dhcp_enabled: dhcp enabled or not for BMC nic
    :type dhcp_enabled: string
    :params static_ip: static ip for BMC nic
    :type static_ip: string
    :params static_gateway: static gateway for BMC nic
    :type static_gateway: string
    :params static_mask: static mask for BMC nic
    :type static_mask: string
    :returns: returns set result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
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
        return result

    # Get the manager url response resource
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % ( 
            manager_url, response_manager_url.status, error_message)}
        return result

    target_ethernet_uri = None
    target_ethernet_current_setting = None
    nic_addr = ip.split(':')[0]  # split port if existing
    for request in response_manager_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            return result

        if 'EthernetInterfaces' not in  response_url.dict:
            continue

        request_url = response_url.dict["EthernetInterfaces"]["@odata.id"]
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            return result

        # Find target EthernetInterface
        for nic_request in response_url.dict['Members']:
            sub_request_url = nic_request['@odata.id']
            sub_response_url = REDFISH_OBJ.get(sub_request_url, None)
            if sub_response_url.status != 200:
                error_message = utils.get_extended_error(sub_response_url)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    sub_request_url, sub_response_url.status, error_message)}
                return result

            data = sub_response_url.dict
            if '"' + nic_addr + '"' in str(data) or "'" + nic_addr + "'" in str(data):
                target_ethernet_uri = sub_request_url
                target_ethernet_current_setting = data
                break

        if target_ethernet_uri is not None:
            break

    if target_ethernet_uri is None:
        return {'ret': False, 'msg': "No matched EthernetInterface found under Manager"}

    # convert input to payload and check validity
    payload = {}
    payload["DHCPv4"] = {}
    if dhcp_enabled == "1":
        payload["DHCPv4"]["DHCPEnabled"] = True
    else:
        payload["DHCPv4"]["DHCPEnabled"] = False
    if static_ip is not None or static_gateway is not None or static_mask is not None:
        payload["IPv4StaticAddresses"] = list()
        config = {}
        if static_ip is not None:
            config["Address"] = static_ip
        if static_gateway is not None:
            config["Gateway"] = static_gateway
        if static_mask is not None:
            config["SubnetMask"] = static_mask
        payload["IPv4StaticAddresses"].append(config)

    # If no need change, nothing to do. If error detected, report it
    need_change = False
    for property in payload.keys():
        set_value = payload[property]
        cur_value = target_ethernet_current_setting[property]
        # type is simple(not dict/list)
        if not isinstance(set_value, dict) and not isinstance(set_value, list):
            if set_value != cur_value:
                need_change = True
        # type is dict
        if isinstance(set_value, dict):
            for subprop in payload[property].keys():
                if subprop not in target_ethernet_current_setting[property]:
                    return {'ret': False, 'msg': "Sub-property %s is invalid" % subprop}
                sub_set_value = payload[property][subprop]
                sub_cur_value = target_ethernet_current_setting[property][subprop]
                if sub_set_value != sub_cur_value:
                    need_change = True
        # type is list
        if isinstance(set_value, list):
            for i in range(len(set_value)):
                for subprop in payload[property][i].keys():
                    if subprop not in target_ethernet_current_setting[property][i]:
                        return {'ret': False, 'msg': "Sub-property %s is invalid" % subprop}
                    sub_set_value = payload[property][i][subprop]
                    sub_cur_value = target_ethernet_current_setting[property][i][subprop]
                    if sub_set_value != sub_cur_value:
                        need_change = True

    if not need_change:
        return {'ret': True, 'changed': False, 'msg': "Manager NIC already set"}

    # perform set via patch
    headers = {"If-Match": "*"}
    response_network_url = REDFISH_OBJ.patch(target_ethernet_uri, body=payload, headers=headers)
    if response_network_url.status in [200,204]:
        result = {'ret': True, 'msg': "Set BMC ip config successfully"}
    else:
        error_message = utils.get_extended_error(response_network_url)
        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                  target_ethernet_uri, response_network_url.status, error_message)}
    return result


def add_helpmessage(argget):
    argget.add_argument('--dhcpenabled', type=str, choices = ["0", "1"], required=True,
                        help='Indicates if DHCP is enabled or disabled for the bmc nic. (0:false, 1:true)')
    argget.add_argument('--staticip', type=str, required=False, help='Indicates static ip for the manager nic. It will be ignored when dhcpenabled is set to 1')
    argget.add_argument('--staticgateway', type=str, required=False, help='Indicates static gateway for the manager nic. It will be ignored when dhcpenabled is set to 1')
    argget.add_argument('--staticmask', type=str, required=False, help='Indicates static subnetmask for the manager nic. It will be ignored when dhcpenabled is set to 1')


def add_parameter():
    """Add set manager ip parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["dhcpenabled"] = args.dhcpenabled
    if args.dhcpenabled == "0":
        parameter_info["staticip"] = args.staticip
        parameter_info["staticgateway"] = args.staticgateway
        parameter_info["staticmask"] = args.staticmask
    else:
        parameter_info["staticip"] = None
        parameter_info["staticgateway"] = None
        parameter_info["staticmask"] = None
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # set manager ip and check result
    result = set_bmc_ip(ip, login_account, login_password, parameter_info["dhcpenabled"],
                            parameter_info["staticip"], parameter_info["staticgateway"], parameter_info["staticmask"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

