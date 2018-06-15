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
import logging
import json
import redfish
from redfish import redfish_logger
import lenovo_utils as utils


def get_bmc_info(ip, login_account, login_password):
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    # Login into the server and create a session
    try:
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    bmc_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
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
            Model = response_manager_url.dict["Model"]
            DateTime = response_manager_url.dict["DateTime"]
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
            KVMIP = response_network_protocol_url.dict["KVMIP"]["Port"]
            IPMI = response_network_protocol_url.dict["IPMI"]["Port"]
            SSDP = response_network_protocol_url.dict["SSDP"]["Port"]
            SSH = response_network_protocol_url.dict["SSH"]["Port"]
            SNMP = response_network_protocol_url.dict["SNMP"]["Port"]
            Virtual_Media = response_network_protocol_url.dict["VirtualMedia"]["Port"]
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
            bmc_details.append(bmc_info)
        else:
            result = {'ret': False, 'msg': "response network protocol url Error code %s" % response_network_protocol_url.status}
            REDFISH_OBJ.logout()
            return result
        response_nics_url = REDFISH_OBJ.get(nics_url, None)
        if response_nics_url.status == 200:
            nic_count = response_nics_url.dict["Members@odata.count"]
            x = 0
            for x in range (0, 1):  #for now
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
                    bmc_details.append(serial_info)
                else:
                    result = {'ret': False, 'msg': "response serial_x_url Error code %s" % response_serial_x_url.status}
                    REDFISH_OBJ.logout()
                    return result
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
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    result = get_bmc_info(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])