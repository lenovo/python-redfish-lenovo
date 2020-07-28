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
import lenovo_utils as utils


def lenovo_set_serial_interfaces(ip, login_account, login_password, interfaceid, bitrate, stopbits, parity, enabled, climode, state, clikey):
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
    :params climode: This property shall indicate command-line interface mode
    :type climode: string
    :params state: Specify the enabled and disabled state of the serial interface
    :type state: string
    :params clikey: The key sequence to exit serial redirection and enter CLI
    :type clikey: string
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
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    try:
        base_response = REDFISH_OBJ.get('/redfish/v1', None)
        if base_response.status == 200:
            # get the managers url
            managers_url = base_response.dict['Managers']['@odata.id']
        else:
            try:
                error_message = utils.get_extended_error(base_response)
            except:
                error_message = base_response
            result = {'ret': False, 'msg': "response base url Error code %s \nerror_message: %s" % (base_response.status, error_message)}
            
            return result

        managers_url_response = REDFISH_OBJ.get(managers_url, None)
        if managers_url_response.status == 200:
            # get the managers url collection
            managers_url_collection = managers_url_response.dict['Members']
        else:
            try:
                error_message = utils.get_extended_error(managers_url_response)
            except:
                error_message = managers_url_response
            result = {'ret': False, 'msg': "response managers_url Error code %s \nerror_message: %s" % (managers_url_response.status, error_message)}
            
            return result

        # Get the manager url from managers url collection
        for i in managers_url_collection:
            manager_x_url = i["@odata.id"]
            manager_x_url_response = REDFISH_OBJ.get(manager_x_url, None)
            if manager_x_url_response.status == 200:
                # Get the serial interfaces url
                serial_interfaces_url = manager_x_url_response.dict['SerialInterfaces']['@odata.id']
            else:
                try:
                    error_message = utils.get_extended_error(manager_x_url_response)
                except:
                    error_message = manager_x_url_response
                result = {'ret': False, 'msg': "response manager_x_url Error code %s \nerror_message: %s" % (manager_x_url_response.status, error_message)}
                return result

            # Get the serial interfaces url collection
            serial_interfaces_url_response = REDFISH_OBJ.get(serial_interfaces_url, None)
            if serial_interfaces_url_response.status == 200:
                serial_interfaces_url_collection = serial_interfaces_url_response.dict['Members']
            else:
                try:
                   error_message = utils.get_extended_error(serial_interfaces_url_response)
                except:
                   error_message = serial_interfaces_url_response
                result = {'ret': False, 'msg': "response serial_interfaces_url_response Error code %s \nerror_message: %s" % (serial_interfaces_url_response.status, error_message)}
                return result

            # Get the serial interfaces url form serial interfaces url collection
            try:
                index = int(interfaceid) - 1
                if(index == -1):
                    result = {'ret': False, 'msg': "The specified Interface Id does not exist."}
                    return result
                serial_interfaces_x_url = serial_interfaces_url_collection[index]['@odata.id']
                body = {}
                
                # Build body for set serial intervaces properies value
                if bitrate:
                    body['BitRate'] = bitrate
                if parity:
                    body['Parity'] = parity
                if stopbits:
                    body['StopBits'] = stopbits
                if enabled:
                    # Check InterfaceEnabled and SerialInterfaceState value.
                    if (bool(int(enabled)) == False and state == "Enabled") or (bool(int(enabled)) == True and state == "Offline"):
                        result = {'ret':False, 'msg':'InterfaceEnabled is "true" then SerialInterfaceState must be "Enabled".InterfaceEnabled is "false" then SerialInterfaceState must be "Offline".'}     
                        return result
                    body['InterfaceEnabled'] = bool(int(enabled))
                else:
                    if state == "Enable":
                        body['InterfaceEnabled'] = True
                    elif state == "Offline":
                        body['InterfaceEnabled'] = False
                
                # Get serial intefaces resource
                response_serial_interfaces_x_url = REDFISH_OBJ.get(serial_interfaces_x_url, None)

                # Determine and set the OEM attribute value of the serial
                if response_serial_interfaces_x_url.status == 200:
                    if "Oem" in response_serial_interfaces_x_url.dict:
                        if "Lenovo" in response_serial_interfaces_x_url.dict['Oem']:
                            lenovo = {}
                            if climode:
                                lenovo["CLIMode"] = climode
                            if state:
                                lenovo['SerialInterfaceState'] = state
                            else:
                                try:
                                    if body['InterfaceEnabled']:
                                        lenovo['SerialInterfaceState'] = "Enabled"
                                    else:
                                        lenovo['SerialInterfaceState'] = "Offline"
                                except KeyError:
                                    pass
                            if clikey:
                                lenovo['EnterCLIKeySequence'] = clikey
                else:
                    try:
                        error_message = utils.get_extended_error(response_serial_interfaces_x_ur)
                    except:
                        error_message = response_serial_interfaces_x_ur
                    result = {'ret': False, 'msg': "response response_serial_interfaces_x_ur Error code %s \nerror_message: %s" % (response_serial_interfaces_x_ur.status, error_message)}
                    return result

                # Add in serial oem properies value to body
                try:
                    if lenovo:
                        body["Oem"] = {"Lenovo":lenovo}
                except:
                    pass

                # check whether the specified interface is valid
                if "BitRate" not in response_serial_interfaces_x_url.dict:
                    result = {'ret': False, 'msg': "The specified Interface Id %s has no BitRate property, not valid." %(interfaceid)}
                    return result

                if "@odata.etag" in response_serial_interfaces_x_url.dict:
                    etag = response_serial_interfaces_x_url.dict['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}


                # Request set serial interface
                serial_interfaces_x_url_response = REDFISH_OBJ.patch(serial_interfaces_x_url, body=body, headers=headers)
                if serial_interfaces_x_url_response.status == 200:
                    result = {'ret': True, 'msg': '%s set Successful'% [key+':'+str(value) for key, value in body.items()]}
                else:
                    try:
                        error_message = utils.get_extended_error(serial_interfaces_x_url_response)
                    except:
                        error_message = serial_interfaces_x_url_response
                    result = {'ret': False, 'msg': "response serial_interfaces_x_url_response Error code %s \nerror_message: %s" % (serial_interfaces_x_url_response.status, error_message)}
            except IndexError:
                result = {'ret': False, 'msg': "The specified Interface Id does not exist."}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result       


import argparse
def add_parameter():
    """Add set serial interfaces attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--interfaceid', type=str, default='1', help='Serial interface instance id. (default instance id is 1)')
    argget.add_argument('--bitrate', type=str, default='', help='This property indicates the transmit and receive speed of the serial connection. Support: [9600, 19200, 38400, 57600, 115200]')
    argget.add_argument('--stopbits', type=str, default='', help='This property indicates the stop bits for the serial connection. Support:["1","2"].')
    argget.add_argument('--parity', type=str, default='', help='This property indicates parity information for a serial connection. Support: ["None", "Even", "Odd"]')
    argget.add_argument('--enabled', type=str, default='', help='This property indicates whether this interface is enabled. Support:(0:false,1:true)')
    argget.add_argument('--climode', type=str, default='', help='This property indicates command-line interface mode. Support:["Compatible", "UserDefined"]')
    argget.add_argument('--state', type=str, default='', help='This property indicates the state of the serial interface enabled or disabled. Support:["Enabled", "Offline"]')
    argget.add_argument('--clikey', type=str, default='', help='The key sequence to exit serial redirection and enter CLI.')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    # Parse the added parameters
    try:
        parameter_info['bitrate'] = args.bitrate
        parameter_info['stopbits'] = args.stopbits
        parameter_info['parity'] = args.parity
        parameter_info['interfaceid'] = args.interfaceid
        parameter_info['enabled'] = args.enabled
        parameter_info['climode'] = args.climode
        parameter_info['state'] = args.state
        parameter_info['clikey'] = args.clikey
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
    climode = parameter_info['climode']
    state = parameter_info['state']
    clikey = parameter_info['clikey']
    
    # check parameter for user specified
    if not bitrate and not stopbits and not parity and not enabled and not climode and not state and not clikey:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)
    
    # Set serial interfaces and check result
    result = lenovo_set_serial_interfaces(ip, login_account, login_password, interfaceid, bitrate, stopbits, parity, enabled, climode, state, clikey)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

    
