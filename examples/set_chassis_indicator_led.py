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
import traceback
import lenovo_utils as utils


def set_chassis_indicator_led(ip, login_account, login_password, led_status):
    """set chassis indicator led
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
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    try:
        # Get ComputerBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            chassis_url = response_base_url.dict['Chassis']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
                response_base_url.status, error_message)}
            return result
        # Get response chassis url resource
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status == 200:
            for i in range(response_chassis_url.dict['Members@odata.count']):
                led_url = response_chassis_url.dict['Members'][i]['@odata.id']

                # Get Chassis instance
                response_led_url = REDFISH_OBJ.get(led_url, None)
                if response_led_url.status != 200:
                    error_message = utils.get_extended_error(response_led_url)
                    result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                        led_url, response_led_url.status, error_message)}
                    return result
                if response_chassis_url.dict['Members@odata.count'] > 1 and (not response_led_url.text or'IndicatorLED' not in response_led_url.dict):
                        continue

                # get etag to set If-Match precondition
                if "@odata.etag" in response_led_url.dict:
                    etag = response_led_url.dict['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag, "Content-Type": "application/json"}

                parameter = {"IndicatorLED": led_status}
                patched_url = led_url
                response_url = REDFISH_OBJ.patch(led_url, body=parameter, headers=headers)
                if response_url.status not in [200, 204]:
                    # Some services report the identify LED on the chassis but take the write
                    # only on the ComputerSystem the chassis links to -- one lamp, two
                    # resources, and the chassis copy follows whatever the system is set to.
                    # Nothing in the payload marks it read-only, so the rejected PATCH is the
                    # only signal there is. Follow the link and retry there before giving up.
                    #
                    # Held because the retry below overwrites response_url: the command named
                    # a chassis, so the chassis rejecting the write is the answer the caller
                    # asked for, and reporting only the system's error reads as though the
                    # wrong url had been written to.
                    chassis_error = utils.get_extended_error(response_url)
                    chassis_status = response_url.status
                    for system in response_led_url.dict.get('Links', {}).get('ComputerSystems', []):
                        response_system_url = REDFISH_OBJ.get(system['@odata.id'], None)
                        if response_system_url.status != 200 or 'IndicatorLED' not in response_system_url.dict:
                            continue
                        system_headers = {"If-Match": response_system_url.dict.get('@odata.etag', ''),
                                          "Content-Type": "application/json"}
                        patched_url = system['@odata.id']
                        response_url = REDFISH_OBJ.patch(patched_url, body=parameter, headers=system_headers)
                        if response_url.status in [200, 204]:
                            break
                if response_url.status in [200, 204]:
                    result = {'ret': True, 'msg': "PATCH command successfully completed '%s' request for indicator LED at '%s'" % (
                        led_status, patched_url)}
                else:
                    error_message = utils.get_extended_error(response_url)
                    message = "Url '%s' response Error code %s \nerror_message: %s" % (
                        patched_url, response_url.status, error_message)
                    if patched_url != led_url:
                        message += "\nUrl '%s' rejected it first. response Error code %s \nerror_message: %s" % (
                            led_url, chassis_status, chassis_error)
                    result = {'ret': False, 'msg': message}
                    return result
        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            chassis_url, response_chassis_url.status, error_message)}
            return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--ledstatus', type=str, required=True, help='Input the status of the LED light(Off, Lit, Blinking)')


def add_parameter():
    """Add set chassis indicator led parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['ledstatus'] = args.ledstatus
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
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
