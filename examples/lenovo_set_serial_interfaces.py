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


def set_serial_interfaces(ip, login_account, login_password, bitrate, stopbits, parity, interface):
    """Set serial interfaces
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns set serial interfaces result when succeeded or error message when failed
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
        REDFISH_OBJ.logout()
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
        REDFISH_OBJ.logout()
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
            REDFISH_OBJ.logout()
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
            REDFISH_OBJ.logout()
            return result

        # Get the serial interfaces url form serial interfaces url collection
        # for i in serial_interfaces_url_collection:
        try:
            index = int(interface) - 1
            if(index == -1):
                result = {'ret': False, 'msg': "The specified Interface Id does not exist."}
                return result
            serial_interfaces_x_url = serial_interfaces_url_collection[index]['@odata.id']
            body = {}
            if bitrate:
                body['BitRate'] = bitrate
            if parity:
                body['Parity'] = parity
            if stopbits:
                body['StopBits'] = stopbits
            # if interface:
            #     body['InterfaceEnabled'] = interface

            serial_interfaces_x_url_response = REDFISH_OBJ.patch(serial_interfaces_x_url, body=body)
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

    result['ret'] = True
    # Logout of the current session
    REDFISH_OBJ.logout()
    return result       


import argparse
def add_parameter():
    """Add set serial interfaces attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--bitrate', type=str, default='', help='Fetch from the ADAM variable. Support: [9600, 19200, 38400, 57600, 115200]')
    argget.add_argument('--stopbits', type=str, default='', help='Fetch from the ADAM variable.')
    argget.add_argument('--parity', type=str, default='', help='Fetch from the ADAM variable. Support: ["None", "Even", "Odd"]')
    argget.add_argument('--interface', type=str, default='', help='Fetch from the ADAM variable.')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        bitrate = parameter_info['bitrate']
        stopbits = parameter_info['stopbits']
        parity = parameter_info['parity']
        interface = parameter_info['interface']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)
    
    # Set serial interfaces and check result
    result = set_serial_interfaces(ip, login_account, login_password, bitrate, stopbits, parity, interface)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

    
