###
#
# Lenovo Redfish examples - Get the external PCI cards information
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


def get_pci_external_cards(ip, login_account, login_password, system_id):
    """Get pci external cards  
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns pci external cards when succeeded or error message when failed
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
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct." % repr(e)}
        return result

    pci_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result

    for i in range(len(system)):
        # Get System url to locate Chassis link
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status != 200:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get pcislots collection from Chassis link
        pcislots_collection = []
        members_count = 0
        if 'Chassis' in response_system_url.dict['Links']:
            chassis_url = response_system_url.dict['Links']['Chassis'][0]['@odata.id']
            response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
            if response_chassis_url.status == 200 and 'PCIeSlots' in response_chassis_url.dict:
                request_url = response_chassis_url.dict['PCIeSlots']['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200 and 'Slots' in response_url.dict:
                    pcislots_collection = response_url.dict['Slots']
                    members_count = len(pcislots_collection)

        # Get each pci slot
        for i in range(members_count):
            pci = {}
            # Get members url resource
            if 'Links' in pcislots_collection[i] and 'PCIeDevice' in pcislots_collection[i]['Links']:
                for property in ['HotPluggable', 'Location']:
                    if property in pcislots_collection[i]:
                        pci[property] = pcislots_collection[i][property]
                # Get pci devices for the slot
                pcidevices = list()
                device_links = pcislots_collection[i]['Links']['PCIeDevice']
                for device_link in device_links:
                    pcidevice = {}
                    request_url = device_link['@odata.id']
                    response_url = REDFISH_OBJ.get(request_url, None)
                    print(response_url.dict)
                    for property in ['Id', 'Name', 'Description', 'Status', 'Manufacturer', 'Model', 'PCIeInterface',
                                     'DeviceType', 'SerialNumber', 'PartNumber', 'FirmwareVersion', 'SKU']:
                        if property in response_url.dict:
                            pcidevice[property] = response_url.dict[property]
                    pcidevices.append(pcidevice)
                pci['PCIeDevice'] = pcidevices
                pci_details.append(pci)

    result['ret'] = True
    result['entries'] = pci_details
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
    
    # Get pci external cards and check result
    result = get_pci_external_cards(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

