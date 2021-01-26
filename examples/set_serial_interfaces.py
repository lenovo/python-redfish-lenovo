###
#
# Lenovo Redfish examples - Set the serial interfaces
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
from . import lenovo_utils as utils


def set_serial_interfaces(ip, login_account, login_password, interfaceid, bitrate, stopbits, parity, enabled):
    """Set serial interfaces
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params interfaceid: serial interface instance id
    :type interfaceid: string
    :params bitrate: This property shall indicate the transmit and receive speed of the serial connection
    :type bitrate: string
    :params stopbits: This property shall indicate the stop bits for the serial connection
    :type stopbits: string
    :params parity: This property shall indicate parity information for a serial connection
    :type parity: string
    :params enabled: The value of this property shall be a boolean indicating whether this interface is enabled
    :type enabled: string
    :returns: returns set serial interfaces result when succeeded or error message when failed
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

        id_found = False
        # Get the manager url from managers url collection
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

            # go through all serial interafces to find the interface specified by interfaceid, then change the setting.
            for serial_interafce in serial_interfaces_url_collection:
                serial_interface_url = serial_interafce['@odata.id']
                # Get single serial interface info
                response_serial_interface_url = REDFISH_OBJ.get(serial_interface_url, None)
                if response_serial_interface_url.status == 200:
                    if interfaceid == '' or interfaceid == response_serial_interface_url.dict['Id']:
                        id_found = True
                        # specify interfaceid as first instance's id.
                        interfaceid = response_serial_interface_url.dict['Id']
                        if "@odata.etag" in response_serial_interface_url.dict:
                            etag = response_serial_interface_url.dict['@odata.etag']
                        else:
                            etag = ""
                        headers = {"If-Match": etag}

                        body = {}
                        if bitrate:
                            if "BitRate" not in response_serial_interface_url.dict:
                                result = {'ret': False, 'msg': "No BitRate in interface %s." %(interfaceid)}
                                return result
                            body['BitRate'] = bitrate

                        if parity:
                            if "Parity" not in response_serial_interface_url.dict:
                                result = {'ret': False, 'msg': "No Parity in interface %s." %(interfaceid)}
                                return result
                            body['Parity'] = parity
                            
                        if stopbits:
                            if "StopBits" not in response_serial_interface_url.dict:
                                result = {'ret': False, 'msg': "No StopBits in interface %s." %(interfaceid)}
                                return result                        
                            body['StopBits'] = stopbits
                            
                        if enabled:
                            if "InterfaceEnabled" not in response_serial_interface_url.dict:
                                result = {'ret': False, 'msg': "No InterfaceEnabled in interface %s." %(interfaceid)}
                                return result                        
                            body['InterfaceEnabled'] = bool(int(enabled))

                        # Set serial interface
                        set_serial_interface_response = REDFISH_OBJ.patch(serial_interface_url, body=body, headers=headers)
                        if set_serial_interface_response.status in [200,204]:
                            result = {'ret': True, 'msg': 'Set %s successfully'% [key+':'+str(value) for key, value in body.items()]}
                        else:
                            error_message = utils.get_extended_error(set_serial_interface_response)
                            result = {'ret': False, 'msg': "Error code %s \nerror_message: %s" % (set_serial_interface_response.status, error_message)}
                else:
                    error_message = utils.get_extended_error(response_serial_interface_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        serial_interface_url, response_serial_interface_url.status, error_message)}
                    return result

        if id_found == False:
            result = {'ret': False, 'msg': "The specified Interface Id %s does not exist." % interfaceid}
            return result

    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_parameter():
    """Add set serial interfaces attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--interfaceid', type=str, default='', help='Serial interface instance id. (default is first instance\'s id)')
    argget.add_argument('--bitrate', type=str, default='', help='This property indicates the transmit and receive speed of the serial connection. Support: [9600, 19200, 38400, 57600, 115200]')
    argget.add_argument('--stopbits', type=str, default='', help='This property indicates the stop bits for the serial connection. Support:["1","2"].')
    argget.add_argument('--parity', type=str, default='', help='This property indicates parity information for a serial connection. Support: ["None", "Even", "Odd"]')
    argget.add_argument('--enabled', type=str, default='', help='This property indicates if this interface is enabled. Support:(0:false,1:true)')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    # Parse the added parameters
    try:
        parameter_info['bitrate'] = args.bitrate
        parameter_info['stopbits'] = args.stopbits
        parameter_info['parity'] = args.parity
        parameter_info['interfaceid'] = args.interfaceid
        parameter_info['enabled'] = args.enabled
    except:
        pass
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    bitrate = parameter_info['bitrate']
    stopbits = parameter_info['stopbits']
    parity = parameter_info['parity']
    interfaceid = parameter_info['interfaceid']
    enabled = parameter_info['enabled']
    
    # check parameter for user specified
    if not bitrate and not stopbits and not parity and not enabled:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)
    
    # Set serial interfaces and check result
    result = set_serial_interfaces(ip, login_account, login_password, interfaceid, bitrate, stopbits, parity, enabled)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

    
