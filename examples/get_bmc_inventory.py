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


def get_bmc_info(ip, login_account, login_password, system_id):
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
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
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
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # GET the Manager resource
            manager_url = response_system_url.dict["Links"]["ManagedBy"][0]["@odata.id"]
        else:
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        if response_manager_url.status == 200:
            # Get Manager NetworkProtocol resource
            network_protocol_url = response_manager_url.dict["NetworkProtocol"]["@odata.id"]
            # GET Mangaer EtherNetInterfaces resources
            nics_url = response_manager_url.dict["EthernetInterfaces"]["@odata.id"]

            FirmwareVersion = response_manager_url.dict["FirmwareVersion"]
            if 'Model' in response_manager_url.dict:
                Model = response_manager_url.dict["Model"]
            else:
                Model = ""
            if 'DateTime' in response_manager_url.dict:
                DateTime = response_manager_url.dict["DateTime"]
            else:
                DateTime = ""
            bmc_info['FirmwareVersion'] = FirmwareVersion
            bmc_info['Model'] = Model
            bmc_info['DateTime'] = DateTime
        else:
            result = {'ret': False, 'msg': "response manager url Error code %s" % response_manager_url.status}
            REDFISH_OBJ.logout()
            return result
        response_network_protocol_url = REDFISH_OBJ.get(network_protocol_url, None)
        if response_network_protocol_url.status == 200:
            # Get the BMC information
            FQDN = response_network_protocol_url.dict["FQDN"]
            HostName = response_network_protocol_url.dict["HostName"]
            HTTP = response_network_protocol_url.dict["HTTP"]["Port"]
            HTTPs = response_network_protocol_url.dict["HTTPS"]["Port"]
            SSH = response_network_protocol_url.dict["SSH"]["Port"]
            SNMP = response_network_protocol_url.dict["SNMP"]["Port"]
            if "KVMIP" in response_network_protocol_url.dict :
                KVMIP = response_network_protocol_url.dict["KVMIP"]["Port"]
            else:
                KVMIP = ""
            if "Port" in response_network_protocol_url.dict :
                IPMI = response_network_protocol_url.dict["IPMI"]["Port"]
            else:
                IPMI = ""
            if "SSDP" in response_network_protocol_url.dict :
                SSDP = response_network_protocol_url.dict["SSDP"]["Port"]
            else:
                SSDP = ""
            if "VirtualMedia" in response_network_protocol_url.dict :
                Virtual_Media = response_network_protocol_url.dict["VirtualMedia"]["Port"]
            else:
                Virtual_Media = ""
            bmc_info['FQDN'] = FQDN
            bmc_info['HostName'] = HostName
            bmc_info['HTTP'] = HTTP
            bmc_info['HTTPs'] = HTTPs
            bmc_info['KVMIP'] = KVMIP
            bmc_info['IPMI'] = IPMI
            bmc_info['SSDP'] = SSDP
            bmc_info['SSH'] = SSH
            bmc_info['SNMP'] = SNMP
            bmc_info['VirtualMedia'] = Virtual_Media
        else:
            result = {'ret': False, 'msg': "response network protocol url Error code %s" % response_network_protocol_url.status}
            REDFISH_OBJ.logout()
            return result
        response_nics_url = REDFISH_OBJ.get(nics_url, None)
        if response_nics_url.status == 200:
            nic_count = response_nics_url.dict["Members@odata.count"]
            x = 0
            for x in range (0, 1):  
                nic_x_url = response_nics_url.dict["Members"][x]["@odata.id"]
                response_nic_x_url = REDFISH_OBJ.get(nic_x_url, None)
        else:
            result = {'ret': False, 'msg': "response nics url Error code %s" % response_nics_url.status}
            REDFISH_OBJ.logout()
            return result
        # GET Manager SerialInterfaces resources
        serial_url = response_manager_url.dict["SerialInterfaces"]["@odata.id"]
        response_serial_url = REDFISH_OBJ.get(serial_url, None)
        if response_serial_url.status == 200:
            serial_count = response_serial_url.dict["Members@odata.count"]
            x = 0
            serial_info_list = []
            for x in range (0, serial_count):
                serial_info = {}
                serial_x_url = response_serial_url.dict["Members"][x]["@odata.id"]
                response_serial_x_url = REDFISH_OBJ.get(serial_x_url, None)
                if response_serial_x_url.status == 200:
                    Id = response_serial_x_url.dict["Id"]
                    BitRate = response_serial_x_url.dict["BitRate"]
                    Parity = response_serial_x_url.dict["Parity"]
                    StopBits = response_serial_x_url.dict["StopBits"]
                    FlowControl = response_serial_x_url.dict["FlowControl"]
                    serial_info['Id'] = Id
                    serial_info['BitRate'] = BitRate
                    serial_info['Parity'] = Parity
                    serial_info['StopBits'] = StopBits
                    serial_info['FlowControl'] = FlowControl
                    serial_info_list.append(serial_info)
                else:
                    result = {'ret': False, 'msg': "response serial_x_url Error code %s" % response_serial_x_url.status}
                    REDFISH_OBJ.logout()
                    return result
            bmc_info['serial_info'] = serial_info_list
            bmc_details.append(bmc_info)
        else:
            result = {'ret': False, 'msg': "response serial url Error code %s" % response_serial_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = bmc_details
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
    
    # Get BMC inventory and check result
    result = get_bmc_info(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])