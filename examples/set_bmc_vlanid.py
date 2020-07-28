###
#
# Lenovo Redfish examples - Set BMC vlan id
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


def set_bmc_vlanid(ip, login_account, login_password, vlanid, vlanEnable):
    """Set BMC vlan id    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params vlanid: vlan id by user specified
    :type vlanid: string
    :params vlanEnable: vlanenable type by user specified
    :type vlanEnable: string
    :returns: returns set manager vlanid result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://"+ip
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    try:
        # GET the managers url
        base_url = "/redfish/v1"
        response_base_url = REDFISH_OBJ.get(base_url, None)
        if response_base_url.status == 200:
            managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
            REDFISH_OBJ.logout()
            return result
        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status == 200:
            count = response_managers_url.dict["Members@odata.count"]
            for i in range(count):
                manager_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_url = REDFISH_OBJ.get(manager_url, None)

                # Get the ethernet interface url
                if response_manager_url.status == 200:
                    ethernet_interface = response_manager_url.dict['EthernetInterfaces']['@odata.id']
                    response_ethernet_interface = REDFISH_OBJ.get(ethernet_interface, None)
                    if response_ethernet_interface.status == 200:
                        vlan_found = False
                        for i in range(response_ethernet_interface.dict['Members@odata.count']):
                            interface_url = response_ethernet_interface.dict['Members'][i]['@odata.id']
                            if "NIC" in interface_url or "eth" in interface_url:

                                # get etag to set If-Match precondition
                                response_interface_url = REDFISH_OBJ.get(interface_url, None)
                                if response_interface_url.status != 200:
                                    error_message = utils.get_extended_error(response_interface_url)
                                    result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                                        interface_url, response_interface_url.status, error_message)}
                                    return result

                                if "VLAN" not in response_interface_url.text:
                                    continue
                                vlan_found = True
                                
                                if "@odata.etag" in response_interface_url.dict:
                                    etag = response_interface_url.dict['@odata.etag']
                                else:
                                    etag = ""
                                headers = {"If-Match": etag}

                                ivlanid = int(vlanid)
                                parameter = {"VLAN":{"VLANId":ivlanid,"VLANEnable": bool(int(vlanEnable))}}
                                response_interface_url = REDFISH_OBJ.patch(interface_url, body=parameter, headers=headers)
                                if response_interface_url.status in [200,204]:
                                    result = {'ret': True, 'msg': "set BMC vlanid successfully"}
                                else:
                                    error_message = utils.get_extended_error(response_interface_url)
                                    result = {'ret': False,
                                              'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                                  interface_url, response_interface_url.status,
                                                  error_message)}
                                    return result
                        if vlan_found == False:
                            result = {'ret': False, 'msg': "VLAN does not exist."}
                    else:
                        error_message = utils.get_extended_error(response_ethernet_interface)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                            ethernet_interface, response_ethernet_interface.status, error_message)}
                        return result
                else:
                    error_message = utils.get_extended_error(response_manager_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        manager_url, response_manager_url.status, error_message)}
                    return result
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                managers_url, response_managers_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--vlanid', type=str, required=True, help='Input the vlanid of BMC')
    parser.add_argument('--vlanenable', type=str, required=True, help='0:false, 1:true')


def add_parameter():
    """Add manager vlanid parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['vlanid'] = args.vlanid
    parameter_info['vlanEnable'] = args.vlanenable
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        vlanid = parameter_info['vlanid']
        vlanEnable = parameter_info['vlanEnable']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set manager vlanid result and check result
    result = set_bmc_vlanid(ip, login_account, login_password, vlanid, vlanEnable)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
