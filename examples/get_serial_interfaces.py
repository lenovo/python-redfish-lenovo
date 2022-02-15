###
#
# Lenovo Redfish examples - Get the serial interfaces
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


def get_serial_interfaces(ip, login_account, login_password, interfaceid):
    """Get serial interfaces
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params interfaceid: serial interface instance id
    :type interfaceid: string
    :returns: returns get serial interfaces result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
    
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result
        
    try:
        base_response = REDFISH_OBJ.get('/redfish/v1', None)
        if base_response.status == 200:
            # Get the managers url
            managers_url = base_response.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(base_response)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (base_response.status, error_message)}
            return result

        managers_url_response = REDFISH_OBJ.get(managers_url, None)
        if managers_url_response.status == 200:
            # Get the managers url collection
            managers_url_collection = managers_url_response.dict['Members']
        else:
            error_message = utils.get_extended_error(managers_url_response)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (managers_url, managers_url_response.status, error_message)}
            return result

        # Get the manager url from managers url collection
        serial_details_all = []
        id_found = False
        for manager in managers_url_collection:
            manager_url = manager["@odata.id"]
            manager_url_response = REDFISH_OBJ.get(manager_url, None)
            if manager_url_response.status == 200:
                # Get the serial interfaces url
                serial_interfaces_url = manager_url_response.dict['SerialInterfaces']['@odata.id']
            else:
                error_message = utils.get_extended_error(manager_url_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (manager_url, manager_url_response.status, error_message)}
                return result

            # Get the serial interfaces url collection
            serial_interfaces_url_response = REDFISH_OBJ.get(serial_interfaces_url, None)
            if serial_interfaces_url_response.status == 200:
                serial_interfaces_url_collection = serial_interfaces_url_response.dict['Members']
            else:
                error_message = utils.get_extended_error(serial_interfaces_url_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (serial_interfaces_url, serial_interfaces_url_response.status, error_message)}
                return result


            # go through all serial interafces
            for serial_interafce in serial_interfaces_url_collection:
                serial_interface_url = serial_interafce['@odata.id']
                # Get single serial interface info
                response_serial_interface_url = REDFISH_OBJ.get(serial_interface_url, None)

                if response_serial_interface_url.status == 200:
                    serial_interface_dict = {}
                    for serial_property in ['Id', 'InterfaceEnabled', 'Name', 'SignalType', 'DataBits', 'StopBits', 
                        'Parity', 'BitRate', 'FlowControl']:
                        if serial_property in response_serial_interface_url.dict:
                            serial_interface_dict[serial_property] = response_serial_interface_url.dict[serial_property]

                    if interfaceid != '' and interfaceid == response_serial_interface_url.dict['Id']:
                        id_found = True
                        result['ret'] = True
                        result['entries'] = serial_interface_dict
                        return result
                    else:
                        serial_details_all.append(serial_interface_dict)
                        continue
                else:
                    error_message = utils.get_extended_error(response_serial_interface_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        serial_interface_url, response_serial_interface_url.status, error_message)}
                    return result

        if interfaceid != '' and id_found == False:
            result = {'ret': False, 'msg': "The specified Interface Id %s does not exist." % interfaceid}
            return result

        result['ret'] = True
        result['entries'] = serial_details_all
        return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s" % repr(e)}
        return result
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass


import argparse
def add_parameter():
    """Add get serial interfaces attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--interfaceid', type=str, default='', help='Serial interface instance id(default to get all serial interfaces)')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    # Parse the added parameters
    parameter_info['interfaceid'] = args.interfaceid
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    interfaceid = parameter_info['interfaceid']
    
    
    # Set serial interfaces and check result
    result = get_serial_interfaces(ip, login_account, login_password, interfaceid)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

