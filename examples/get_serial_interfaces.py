###
#
# Lenovo Redfish examples - Get the serial interfaces
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
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
    
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check if username, password, IP are correct"}
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
        serial_details = []
        for i in managers_url_collection:
            manager_x_url = i["@odata.id"]
            manager_x_url_response = REDFISH_OBJ.get(manager_x_url, None)
            if manager_x_url_response.status == 200:
                # Get the serial interfaces url
                serial_interfaces_url = manager_x_url_response.dict['SerialInterfaces']['@odata.id']
            else:
                error_message = utils.get_extended_error(manager_x_url_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (manager_x_url, manager_x_url_response.status, error_message)}
                return result

            # Get the serial interfaces url collection
            serial_interfaces_url_response = REDFISH_OBJ.get(serial_interfaces_url, None)
            if serial_interfaces_url_response.status == 200:
                serial_interfaces_url_collection = serial_interfaces_url_response.dict['Members']
            else:
                error_message = utils.get_extended_error(serial_interfaces_url_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (serial_interfaces_url, serial_interfaces_url_response.status, error_message)}
                return result

            # Get the serial interfaces url form serial interfaces url collection
            try:
                if interfaceid:
                    index = int(interfaceid) - 1
                    if(index == -1):
                        result = {'ret': False, 'msg': "The specified Interface Id does not exist."}
                        return result
                else:
                    index = 0
                serial_interfaces_x_url = serial_interfaces_url_collection[index]['@odata.id']
                response_serial_interfaces_x_url = REDFISH_OBJ.get(serial_interfaces_x_url, None)
                if response_serial_interfaces_x_url.status == 200:
                    serial_interfaces_dict = {}
                    serial_interfaces_dict['Id'] = response_serial_interfaces_x_url.dict['Id']
                    serial_interfaces_dict['InterfaceEnabled'] = response_serial_interfaces_x_url.dict['InterfaceEnabled']
                    serial_interfaces_dict['Name'] = response_serial_interfaces_x_url.dict['Name']
                    serial_interfaces_dict['SignalType'] = response_serial_interfaces_x_url.dict['SignalType']
                    serial_interfaces_dict['DataBits'] = response_serial_interfaces_x_url.dict['DataBits']
                    serial_interfaces_dict['StopBits'] = response_serial_interfaces_x_url.dict['StopBits']
                    serial_interfaces_dict['Parity'] = response_serial_interfaces_x_url.dict['Parity']
                    serial_interfaces_dict['BitRate'] = response_serial_interfaces_x_url.dict['BitRate']
                    serial_interfaces_dict['FlowControl'] = response_serial_interfaces_x_url.dict['FlowControl']
                    serial_details.append(serial_interfaces_dict)
                else:
                    error_message = utils.get_extended_error(response_serial_interfaces_x_ur)
                    result = {'ret': False, 'msg': "Url '%s'response Error code %s \nerror_message: %s" % (serial_interfaces_x_url, response_serial_interfaces_x_ur.status, error_message)}
                    return result
            except IndexError:
                result = {'ret': False, 'msg': "The specified Interface Id does not exist."}
                return result
        result['ret'] = True
        result['entries'] = serial_details    
    except Exception as e:
        result = {'ret':False, 'msg':"error_message:%s" %(e)}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result  


import argparse
def add_parameter():
    """Add set serial interfaces attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--interfaceid', type=str, default='', help='Serial interface instance id(default first instance)')
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
        sys.stderr.write(result['msg'])

    
