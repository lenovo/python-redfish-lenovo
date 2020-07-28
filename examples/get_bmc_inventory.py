###
#
# Lenovo Redfish examples - Get the BMC information
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
import json
import redfish
import lenovo_utils as utils


def get_bmc_inventory(ip, login_account, login_password, system_id):
    """Get BMC inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns BMC inventory when succeeded or error message when failed
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    bmc_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        bmc_info = {}

        # Get the manager url
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # GET the Manager resource
            manager_url = response_system_url.dict["Links"]["ManagedBy"][0]["@odata.id"]
        else:
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get the BMC information
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        if response_manager_url.status == 200:
            for bmc_property in ['FirmwareVersion', 'Model', 'DateTime', 'DateTimeLocalOffset']:
                if bmc_property in response_manager_url.dict:
                    bmc_info[bmc_property] = response_manager_url.dict[bmc_property]
        else:
            result = {'ret': False, 'msg': "response manager url Error code %s" % response_manager_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get Manager NetworkProtocol resource
        if "NetworkProtocol" in response_manager_url.dict:
            network_protocol_url = response_manager_url.dict["NetworkProtocol"]["@odata.id"]
            response_network_protocol_url = REDFISH_OBJ.get(network_protocol_url, None)
            if response_network_protocol_url.status == 200:
                for netprotocol_property in ['FQDN', 'HostName', 'HTTP', 'HTTPS', 'SSH', 'SNMP', 'KVMIP',
                    'IPMI', 'SSDP', 'VirtualMedia']:
                    if netprotocol_property in response_network_protocol_url.dict:
                        bmc_info[netprotocol_property] = response_network_protocol_url.dict[netprotocol_property]
            else:
                result = {'ret': False, 'msg': "response network protocol url Error code %s" % response_network_protocol_url.status}
                REDFISH_OBJ.logout()
                return result

        # GET Manager SerialInterfaces resources
        if "SerialInterfaces" in response_manager_url.dict:
            serial_url = response_manager_url.dict["SerialInterfaces"]["@odata.id"]
            response_serial_url = REDFISH_OBJ.get(serial_url, None)
            serial_count = 0
            if response_serial_url.status == 200:
                serial_count = response_serial_url.dict["Members@odata.count"]
            else:
                result = {'ret': False, 'msg': "response serial url Error code %s" % response_serial_url.status}
                REDFISH_OBJ.logout()
                return result
            serial_info_list = []
            for x in range (0, serial_count):
                serial_info = {}
                serial_x_url = response_serial_url.dict["Members"][x]["@odata.id"]
                response_serial_x_url = REDFISH_OBJ.get(serial_x_url, None)
                if response_serial_x_url.status == 200:
                    for serial_property in ['Id', 'BitRate', 'Parity', 'StopBits', 'FlowControl']:
                        if serial_property in response_serial_x_url.dict:
                            serial_info[serial_property] = response_serial_x_url.dict[serial_property]
                    serial_info_list.append(serial_info)
                else:
                    result = {'ret': False, 'msg': "response serial_x_url Error code %s" % response_serial_x_url.status}
                    REDFISH_OBJ.logout()
                    return result
            bmc_info['serial_info'] = serial_info_list

        # GET Manager EthernetInterfaces resources
        if "EthernetInterfaces" in response_manager_url.dict:
            ethernet_url = response_manager_url.dict["EthernetInterfaces"]["@odata.id"]
            response_ethernet_url = REDFISH_OBJ.get(ethernet_url, None)
            ethernet_count = 0
            if response_ethernet_url.status == 200:
                ethernet_count = response_ethernet_url.dict["Members@odata.count"]
            else:
                result = {'ret': False, 'msg': "response ethernet url Error code %s" % response_ethernet_url.status}
                REDFISH_OBJ.logout()
                return result
            ethernet_info_list = []
            for x in range (0, ethernet_count):
                ethernet_info = {}
                ethernet_x_url = response_ethernet_url.dict["Members"][x]["@odata.id"]
                response_ethernet_x_url = REDFISH_OBJ.get(ethernet_x_url, None)
                if response_ethernet_x_url.status == 200:
                    for property in ['Id', 'Name', 'MACAddress', 'PermanentMACAddress', 'MTUSize', 'FQDN', 
                        'AutoNeg', 'Status', 'InterfaceEnabled', 'SpeedMbps', 'NameServers', 'StaticNameServers',
                        'DHCPv4', 'DHCPv6', 'IPv4Addresses', 'IPv4StaticAddresses', 'IPv6Addresses', 'IPv6StaticAddresses']:
                        if property in response_ethernet_x_url.dict:
                            ethernet_info[property] = response_ethernet_x_url.dict[property]
                    ethernet_info_list.append(ethernet_info)
                else:
                    result = {'ret': False, 'msg': "response ethernet_x_url Error code %s" % response_ethernet_x_url.status}
                    REDFISH_OBJ.logout()
                    return result
            bmc_info['ethernet_info'] = ethernet_info_list

    bmc_details.append(bmc_info)
    result['ret'] = True
    result['entries'] = bmc_details
    # Logout of the current session
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
    
    # Get BMC inventory and check result
    result = get_bmc_inventory(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
