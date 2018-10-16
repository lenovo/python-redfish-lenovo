###
#
# Lenovo Redfish examples - Get the network information
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


def get_network_info(ip, login_account, login_password, system_id):
    """Get nic inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns nic inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get("/redfish/v1", None)
    if response_base_url.status == 200:
        chassis_url_list = response_base_url.dict['Chassis']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    response_chassis_url_list = REDFISH_OBJ.get(chassis_url_list, None)
    if response_chassis_url_list.status == 200:
        chassis_count = response_chassis_url_list.dict['Members@odata.count']
    else:
        result = {'ret': False, 'msg': "response chassis url Error code %s" % response_chassis_url_list.status}
        REDFISH_OBJ.logout()
        return result
    nic_details = []
    for count in range(chassis_count):
        # GET the Chassis resource
        chassis_url = response_chassis_url_list.dict['Members'][count]['@odata.id']
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status == 200:
            # GET the NetworkAdapters resource from the Chassis resource
            if "NetworkAdapters" in response_chassis_url.dict:
                nic_adapter_url = response_chassis_url.dict["NetworkAdapters"]["@odata.id"]
            else:
                # GET the ComputerSystem resource
                system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
                if not system:
                    result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
                    REDFISH_OBJ.logout()
                    return result
                for i in range(len(system)):
                    system_url = system[i]
                    response_system_url = REDFISH_OBJ.get(system_url, None)
                    if response_system_url.status == 200:
                        # Get the EthernetInterfaces url
                         nic_adapter_url = response_system_url.dict['EthernetInterfaces']['@odata.id']
                    else:
                        result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
                        REDFISH_OBJ.logout()
                        return result

            response_nic_adapter_url = REDFISH_OBJ.get(nic_adapter_url, None)
            if response_nic_adapter_url.status == 200:
                nic_adapter_count = response_nic_adapter_url.dict["Members@odata.count"]
            else:
                result = {'ret': False,
                          'msg': "response nic adapter url Error code %s" % response_nic_adapter_url.status}
                REDFISH_OBJ.logout()
                return result
            nic = 0
            for nic in range(0, nic_adapter_count):
                network = {}
                nic_devices = []
                nic_adapter_x_url = response_nic_adapter_url.dict["Members"][nic]["@odata.id"]
                response_nic_adapter_x_url = REDFISH_OBJ.get(nic_adapter_x_url, None)
                if response_nic_adapter_x_url.status == 200:
                    Network_Adapter_id = response_nic_adapter_x_url.dict["Id"]
                    Name = response_nic_adapter_x_url.dict["Name"]
                    if "Controllers" in response_nic_adapter_x_url.dict:
                        Firmware_Version = response_nic_adapter_x_url.dict["Controllers"][0]["FirmwarePackageVersion"]
                    else:
                        # Get the other nic info
                        MACAddress = response_nic_adapter_x_url.dict["MACAddress"]
                        MTUSize = response_nic_adapter_x_url.dict["MTUSize"]
                        FQDN = response_nic_adapter_x_url.dict["FQDN"]
                        MTUSize = response_nic_adapter_x_url.dict["MTUSize"]
                        AutoNeg = response_nic_adapter_x_url.dict["AutoNeg"]
                        Adapter_Health = response_nic_adapter_x_url.dict["Status"]["Health"]
                        network['Network_Adapter_id'] = Network_Adapter_id
                        network['Name'] = Name
                        network['MACAddress'] = MACAddress
                        network['MTUSize'] = MTUSize
                        network['FQDN'] = FQDN
                        network['MTUSize'] = MTUSize
                        network['AutoNeg'] = AutoNeg
                        network['Adapter_Health'] = Adapter_Health
                        nic_details.append(network)
                        continue
                    Adapter_Health = response_nic_adapter_x_url.dict["Status"]["Health"]
                    network['Network_Adapter_id'] = Network_Adapter_id
                    network['Name'] = Name
                    network['FirmwarePackageVersion'] = Firmware_Version
                    network['Health'] = Adapter_Health
                else:
                    result = {'ret': False,
                              'msg': "response nic_adapter_x_url Error code %s" % response_nic_adapter_x_url.status}
                    REDFISH_OBJ.logout()
                    return result
                port = 0
                # GET the NetworkDeviceFunction resources from each of the NetworkAdapter resources
                nic_dev_url = response_nic_adapter_x_url.dict["NetworkDeviceFunctions"]["@odata.id"]
                response_nic_dev_url = REDFISH_OBJ.get(nic_dev_url, None)
                if response_nic_dev_url.status == 200:
                    nic_dev_count = response_nic_dev_url.dict["Members@odata.count"]
                else:
                    result = {'ret': False, 'msg': "response nic dev url Error code %s" % response_nic_dev_url.status}
                    REDFISH_OBJ.logout()
                    return result
                for dev in range(0, nic_dev_count):
                    NIC_Devices = {}
                    nic_dev_x_url = response_nic_dev_url.dict["Members"][dev]["@odata.id"]
                    response_nic_dev_x_url = REDFISH_OBJ.get(nic_dev_x_url, None)
                    if response_nic_dev_x_url.status == 200:
                        NIC_Device_ID = response_nic_dev_x_url.dict["Id"]
                        Name = response_nic_dev_x_url.dict["Name"]
                        NetDevFuncType = response_nic_dev_x_url.dict["NetDevFuncType"]
                        DeviceEnabled = response_nic_dev_x_url.dict["DeviceEnabled"]
                        MACAddress = response_nic_dev_x_url.dict["Ethernet"]["MACAddress"]
                        MTUSize = response_nic_dev_x_url.dict["Ethernet"]["MTUSize"]
                        Device_Health = response_nic_dev_x_url.dict["Status"]["Health"]
                        NIC_Devices['NIC_Device_ID'] = NIC_Device_ID
                        NIC_Devices['Name'] = Name
                        NIC_Devices['NetDevFuncType'] = NetDevFuncType
                        NIC_Devices['DeviceEnabled'] = DeviceEnabled
                        NIC_Devices['MACAddress'] = MACAddress
                        NIC_Devices['MTUSize'] = MTUSize
                        NIC_Devices['Health'] = Device_Health
                        nic_devices.append(NIC_Devices)
                        # GET the associated NetworkPort resource
                        nic_port_x_url = response_nic_dev_x_url.dict["PhysicalPortAssignment"]["@odata.id"]
                        response_nic_port_x_url = REDFISH_OBJ.get(nic_port_x_url, None)
                        if response_nic_port_x_url.status == 200:
                            Physical_Ports = {}
                            Physical_Port_id = response_nic_port_x_url.dict["PhysicalPortNumber"]
                            Physical_Port_Name = response_nic_port_x_url.dict["Name"]
                            Active_Link_Technology = response_nic_port_x_url.dict["ActiveLinkTechnology"]
                            Port_Maximum_MTU = response_nic_port_x_url.dict["PortMaximumMTU"]
                            Port_Health = response_nic_port_x_url.dict["Status"]["Health"]
                            Physical_Ports['PhysicalPortNumber'] = Physical_Port_id
                            Physical_Ports['Name'] = Physical_Port_Name
                            if "LinkStatus" in response_nic_port_x_url.dict:
                                LinkStatus = response_nic_port_x_url.dict["LinkStatus"]
                                Physical_Ports['LinkStatus'] = LinkStatus
                            Physical_Ports['ActiveLinkTechnology'] = Active_Link_Technology
                            Physical_Ports['PortMaximumMTU'] = Port_Maximum_MTU
                            Physical_Ports['Health'] = Port_Health
                            NIC_Devices['physical_ports'] = Physical_Ports
                            network['nic_devices'] = nic_devices
                        else:
                            result = {'ret': False,
                                      'msg': "response nic_port_x_url Error code %s" % response_nic_port_x_url.status}
                            REDFISH_OBJ.logout()
                            return result
                    else:
                        result = {'ret': False,
                                  'msg': "response nic_dev_x_url Error code %s" % response_nic_dev_url.status}
                        REDFISH_OBJ.logout()
                        return result
                nic_details.append(network)
        else:
            result = {'ret': False, 'msg': "response chassis url Error code %s" % response_chassis_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = nic_details
    # Logout of the current session
    REDFISH_OBJ.logout()
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
    
    # Get nic inventory and check result
    result = get_network_info(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
