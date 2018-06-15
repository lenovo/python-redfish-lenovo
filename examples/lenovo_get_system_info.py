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
import lenovo_utils as utils


def get_system_info(ip, login_account, login_password):
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

    system_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            system = {}
            # Get the system information
            Host_Name = response_system_url.dict["HostName"]
            Model = response_system_url.dict["Model"]
            SerialNumber = response_system_url.dict["SerialNumber"]
            AssetTag = response_system_url.dict["AssetTag"]
            UUID = response_system_url.dict["UUID"]
            Procesors_Model = response_system_url.dict["ProcessorSummary"]["Model"]
            ProcesorsCount = response_system_url.dict["ProcessorSummary"]["Count"]
            Total_Memory = response_system_url.dict["MemorySummary"]["TotalSystemMemoryGiB"]
            BIOS_Version = response_system_url.dict["BiosVersion"]
            system['HostName'] = Host_Name
            system['Model'] = Model
            system['SerialNumber'] = SerialNumber
            system['AssetTag'] = AssetTag
            system['UUID'] = UUID
            system['Procesors_Model'] = Procesors_Model
            system['ProcesorsCount'] = ProcesorsCount
            system['TotalSystemMemoryGiB'] = Total_Memory
            system['BiosVersion'] = BIOS_Version
            system_details.append(system)
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
            for x in range(0, nic_count):
                EtherNetInterfaces = {}
                nic_x_url = response_nics_url.dict["Members"][x]["@odata.id"]
                response_nic_x_url = REDFISH_OBJ.get(nic_x_url, None)
                if response_nic_x_url.status == 200:
                    PermanentMACAddress = response_nic_x_url.dict["PermanentMACAddress"]
                    EtherNetInterfaces['PermanentMACAddress'] = PermanentMACAddress
                    system_details.append(EtherNetInterfaces)
                else:
                    result = {'ret': False, 'msg': "response nic_x_url Error code %s" % response_nic_x_url.status}
                    REDFISH_OBJ.logout()
                    return result

        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        result['ret'] = True
        result['entries'] = system_details
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
    result = get_system_info(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

