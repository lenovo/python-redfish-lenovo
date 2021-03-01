###
#
# Lenovo Redfish examples - Set server asset tag
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
import redfish
import json
import lenovo_utils as utils


def set_server_asset_tag(ip, login_account, login_password, system_id, asset_tag):
    """Set server asset tag
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params asset_tag: asset tag by user specified
    :type asset_tag: string
    :returns: returns set server asset tag result when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            # get etag to set If-Match precondition
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status != 200:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result
            if "@odata.etag" in response_system_url.dict:
                etag = response_system_url.dict['@odata.etag']
            else:
                etag = ""
            headers = {"If-Match": etag}

            # perform patch to set assettag
            parameter = {"AssetTag": asset_tag}
            response_asset_tag = REDFISH_OBJ.patch(system_url, body=parameter, headers=headers)
            if response_asset_tag.status in [200, 204]:
                result = {'ret': True,
                          'msg': "PATCH command successfully completed for set server asset tag to %s" % asset_tag}
            else:
                error_message = utils.get_extended_error(response_asset_tag)
                result = {'ret': False, 'msg': "Url '%s' patch failed. response Error code %s \nerror_message: %s" % (
                    system_url, response_asset_tag.status, error_message)}
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--assettag', type=str, required=True, help='Input the assettag info(Maximum string length of AssetTag is 32)')


def add_parameter():
    """Add set server asset tag parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['asset_tag'] = args.assettag
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get set info from the parameters user specified
    try:
        asset_tag = parameter_info['asset_tag']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set server asset tag result and check result
    result = set_server_asset_tag(ip, login_account, login_password, system_id, asset_tag)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
