###
#
# Lenovo Redfish examples - Get the System information
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
import traceback
import lenovo_utils as utils


def get_system_inventory(ip, login_account, login_password, system_id):
    """Get system inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns system info when succeeded or error message when failed
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

    system_properties = ['Status', 'HostName', 'PowerState', 'Model', 'Manufacturer', 'SystemType',
                      'PartNumber', 'SerialNumber', 'AssetTag', 'ServiceTag', 'UUID', 'SKU',
                      'BiosVersion', 'ProcessorSummary', 'MemorySummary', 'TrustedModules']
    system_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            system = {}
            # Get the system information
            for system_property in system_properties:
                if system_property in response_system_url.dict:
                    system[system_property] = response_system_url.dict[system_property]

            # GET System EtherNetInterfaces resources
            nics_url = response_system_url.dict["EthernetInterfaces"]["@odata.id"]
            response_nics_url = REDFISH_OBJ.get(nics_url, None)
            if response_nics_url.status == 200:
                nic_count = response_nics_url.dict["Members@odata.count"]
            else:
                result = {'ret': False, 'msg': "response nics url Error code %s" % response_nics_url.status}
                REDFISH_OBJ.logout()
                return result
            x = 0
            ethernetinterface = []
            for x in range(0, nic_count):
                EtherNetInterfaces = {}
                nic_x_url = response_nics_url.dict["Members"][x]["@odata.id"]
                response_nic_x_url = REDFISH_OBJ.get(nic_x_url, None)
                if response_nic_x_url.status == 200:
                    if "PermanentMACAddress" in response_nic_x_url.dict:
                        PermanentMACAddress = response_nic_x_url.dict["PermanentMACAddress"]
                        EtherNetInterfaces['PermanentMACAddress'] = PermanentMACAddress
                        ethernetinterface.append(EtherNetInterfaces)
                else:
                    result = {'ret': False, 'msg': "response nic_x_url Error code %s" % response_nic_x_url.status}
                    REDFISH_OBJ.logout()
                    return result

            system['EtherNetInterfaces'] = ethernetinterface
            system_details.append(system)
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        result['ret'] = True
        result['entries'] = system_details
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
    
    # Get system info and check result
    result = get_system_inventory(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

