###
#
# Lenovo Redfish examples - set chassis indicator led
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


import redfish
import sys
import json
import lenovo_utils as utils


def set_chassis_indicator_led(ip, login_account, login_password, led_status):
    """Get BMC inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params led_status: Led status by user specified
    :type led_status: string
    :returns: returns set chassis indicator led result when succeeded or error message when failed
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    
    # Get ComputerBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        chassis_url = response_base_url.dict['Chassis']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    # Get response chassis url resource
    response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
    if response_chassis_url.status == 200:
        for i in range(response_chassis_url.dict['Members@odata.count']):
            led_url = response_chassis_url.dict['Members'][i]['@odata.id']
            led_status = led_status
            parameter = {"IndicatorLED": led_status}
            headers = {"Content-Type": "application/json"}
            response_url = REDFISH_OBJ.patch(led_url, body=parameter, headers=headers)
            if response_url.status == 200:
                result = {'ret': True, 'msg': "PATCH command successfully completed '%s' request for chassis indicator LED" % led_status}
            else:
                result = {'ret': False, 'msg': "response url Error code %s" % response_url.status}
                REDFISH_OBJ.logout()
                return result
    else:
        print("response_chassis_url Error code %s" % response_chassis_url.status)
        result = {'ret': False, 'msg': "response chassis url Error code %s" % response_chassis_url.status}

    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add set chassis indicator led parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--ledstatus', type=str, help='Input the status of the LED light(Off, Lit, Blinking)')
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
        led_status = parameter_info['ledstatus']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set chassis indicator led result and check result
    result = set_chassis_indicator_led(ip, login_account, login_password, led_status)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
