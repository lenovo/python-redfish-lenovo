###
#
# Lenovo Redfish examples - Set system name
#
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
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
import redfish
import json
import traceback
import lenovo_utils as utils


def set_system_name(ip, login_account, login_password, system_name):
    """set system name
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_name: system name
    :type system_name: string
    :returns: returns set result when succeeded or error message when failed
    """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            chassis_url = response_base_url.dict['Chassis']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status == 200:
            #get system name
            for request in response_chassis_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200:
                    # if chassis is not normal skip it
                    if len(response_chassis_url.dict['Members']) > 1 and ("Links" not in response_url.dict or
                            "ComputerSystems" not in response_url.dict["Links"]):
                        continue
                    # if no Location property, skip it
                    if 'Location' not in response_url.dict:
                        continue
                else:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" %
                                                   (request_url, response_url.status, error_message)}
                    return result

                headers = {"If-Match": "*"}
                body = {'Location': {"PostalAddress": {"Name": system_name}}}

                # Send Patch Request to Modify System Name
                response_system_name_url = REDFISH_OBJ.patch(request_url, body=body, headers=headers)
                if response_system_name_url.status in [200, 204]:
                    result = {'ret': True,
                              'msg': "Set system name %s successfully" % system_name}
                    return result
                else:
                    error_message = utils.get_extended_error(response_system_name_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" %
                                                   (request_url, response_system_name_url.status, error_message)}
                    return result

        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                chassis_url, response_chassis_url.status, error_message)}
            return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': 'exception msg %s' %e }
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_helpmessage(argget):
    argget.add_argument('--systemname', type=str, required=True, help='Set system name')


def add_parameter():
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["system_name"] = args.systemname
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info["ip"]
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        system_name = parameter_info["system_name"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # set system name and check result
    result = set_system_name(ip, login_account, login_password, system_name)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
