###
#
# Lenovo Redfish examples - Get Bios attribute
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


def get_bios_attribute(ip, login_account, login_password, system_id, attribute_name):
    """get bios attribute by user specified    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params attribute_name: Bios attribute name by user specified
    :type attribute_name: string
    :returns: returns get bios attribute value when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the ComputerBios resource
                bios_url = response_system_url.dict['Bios']['@odata.id']
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result

            response_bios_url = REDFISH_OBJ.get(bios_url, None)
            if response_bios_url.status == 200:
                attribute = response_bios_url.dict['Attributes']
                bios_attribute = {}
                if attribute_name in attribute.keys():
                    bios_attribute[attribute_name] = attribute[attribute_name]
                    result = {'ret': True, 'msg': bios_attribute}
                else:
                    result = {'ret': False, 'msg': " No this attribute in the bios attribute"}
            elif response_bios_url.status == 400:
                result = {'ret': False, 'msg': 'Not supported on this platform'}
                REDFISH_OBJ.logout()
                return result
            else:
                error_message = utils.get_extended_error(response_bios_url)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    bios_url, response_bios_url.status, error_message)}
                return result
    except Exception as e:
        result = {'ret': False, 'msg': "error message %s" % e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def add_helpmessage(parser):
    parser.add_argument('--name', type=str, required=True, help='Input the attribute name')


def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['attribute_name'] = args.name
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']

    # Get search attribute from the parameters user specified
    try:
        attribute_name = parameter_info['attribute_name']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get bios sttribute value and check result
    result = get_bios_attribute(ip, login_account, login_password,system_id, attribute_name)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
