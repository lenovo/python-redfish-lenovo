###
#
# Lenovo Redfish examples - Get the PCI information
#
# Copyright Notice:
#
# Copyright 2019 Lenovo Corporation
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


def get_pci_inventory(ip, login_account, login_password, system_id):
    """Get pci inventory
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns pci inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1',
                                             cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
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
        # Get pcidevices collection
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status != 200:
            result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (system_url, response_system_url.status)}
            REDFISH_OBJ.logout()
            return result
        pcidevices_collection = []
        members_count = 0
        if 'PCIeDevices' in response_system_url.dict:
            pcidevices_collection = response_system_url.dict['PCIeDevices']
            members_count = len(pcidevices_collection)

        # If no pcidevice in system, try to get pcidevice info from Chassis
        if members_count == 0 and 'Links' in response_system_url.dict and 'Chassis' in response_system_url.dict['Links']:
            chassis_url = response_system_url.dict['Links']['Chassis'][0]['@odata.id']
            response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
            if response_chassis_url.status == 200 and 'PCIeDevices' in response_chassis_url.dict:
                request_url = response_chassis_url.dict['PCIeDevices']['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200 and 'Members' in response_url.dict:
                    pcidevices_collection = response_url.dict['Members']
                    members_count = len(pcidevices_collection)
            elif response_chassis_url.status == 200 and 'Links' in response_chassis_url.dict and 'PCIeDevices' in response_chassis_url.dict['Links']:
                pcidevices_collection = response_chassis_url.dict['Links']['PCIeDevices']
                members_count = len(pcidevices_collection)

        # Get each pci device info
        for i in range(members_count):
            pci = {}
            # Get members url resource
            members_url = pcidevices_collection[i]['@odata.id']
            response_members_url = REDFISH_OBJ.get(members_url, None)
            if response_members_url.status != 200:
                result = {'ret': False,
                          'msg': "Access url %s failed. Error code %s" % (members_url, response_members_url.status)}
                REDFISH_OBJ.logout()
                return result

            for property in ['Id', 'Name', 'Description', 'Status', 'Manufacturer', 'Model', 'DeviceType', 'SerialNumber', 'PartNumber', 'FirmwareVersion', 'SKU']:
                if property in response_members_url.dict:
                    pci[property] = response_members_url.dict[property]

            # Get PCIeFunctions
            pci['PCIeFunctions'] = []
            members = []
            if 'PCIeFunctions' in response_members_url.dict and '@odata.id' in response_members_url.dict['PCIeFunctions'] \
                    and response_members_url.dict['PCIeFunctions']['@odata.id'] is not None:
                response_pciefunc = REDFISH_OBJ.get(response_members_url.dict['PCIeFunctions']['@odata.id'], None)
                if response_pciefunc.status != 200:
                    result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (response_members_url.dict['PCIeFunctions']['@odata.id'], response_pciefunc.status)}
                    REDFISH_OBJ.logout()
                    return result
                for member in response_pciefunc.dict['Members']:
                    members.append(member)
            else:
                if 'Links' in response_members_url.dict and 'PCIeFunctions' in response_members_url.dict['Links']:
                    response_members = response_members_url.dict['Links']['PCIeFunctions']
                    for pciefunc_entry in response_members:
                        members.append(pciefunc_entry)

            for member_url in members:
                pciefunc = {}
                response_pciefunc_member = REDFISH_OBJ.get(member_url['@odata.id'], None)
                for property in ['Id', 'VendorId', 'DeviceId', 'SubsystemId', 'SubsystemVendorId', 'DeviceClass', 'FunctionId', 'FunctionType']:
                    if property in response_pciefunc_member.dict:
                        pciefunc[property] = response_pciefunc_member.dict[property]
                pci['PCIeFunctions'].append(pciefunc)
            pci_details.append(pci)

    result['ret'] = True
    result['entries'] = pci_details
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

    # Get pci inventory and check result
    result = get_pci_inventory(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
