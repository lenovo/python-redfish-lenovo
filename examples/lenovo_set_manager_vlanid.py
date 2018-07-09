###
#
# Lenovo Redfish examples - Set manager vlan id
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


def set_manager_vlanid(ip, login_account, login_password, vlanid, vlanEnable):
    """Set manager vlan id    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
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
                                         password=login_password, default_prefix='/redfish/v1')
    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
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
            if response_manager_url.status == 200:
                ethernet_interface = response_manager_url.dict['EthernetInterfaces']['@odata.id']
                response_ethernet_interface = REDFISH_OBJ.get(ethernet_interface, None)
                if response_ethernet_interface.status == 200:
                    for i in range(response_ethernet_interface.dict['Members@odata.count']):
                        interface_url = response_ethernet_interface.dict['Members'][i]['@odata.id']
                        if "NIC" in interface_url:
                            vlanid = vlanid
                            parameter = {"VLAN":{"VLANId":vlanid,"VLANEnable": bool(int(vlanEnable))}}
                            response_interface_url = REDFISH_OBJ.patch(interface_url, body=parameter)
                            if response_interface_url.status == 200:
                                result = {'ret': True, 'msg': "set manager vlanid successful"}
                            else:
                                result = {'ret': False, 'msg': "response interface url Error code %s" % response_interface_url.status}
                                REDFISH_OBJ.logout()
                                return result
                else:
                    result = {'ret': False, 'msg': "response ethernet interface Error code %s" % response_ethernet_interface.status}
                    REDFISH_OBJ.logout()
                    return result
            else:
                result = {'ret': False, 'msg': "response manager url Error code %s" % response_manager_url.status}
                REDFISH_OBJ.logout()
                return result
    else:
        
        result = {'ret': False, 'msg': "response managers url Error code %s" % response_managers_url.status}
        REDFISH_OBJ.logout()
        return result
        
    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add manager vlanid parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--vlanid', type=str, help='Input the set manager vlanid')
    argget.add_argument('--vlanenable', type=str, help='0:false, 1:true')
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

    # Get set info from the parameters user specified
    try:
        vlanid = parameter_info['vlanid']
        vlanEnable = parameter_info['vlanEnable']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set manager vlanid result and check result
    result = set_manager_vlanid(ip, login_account, login_password, vlanid, vlanEnable)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])