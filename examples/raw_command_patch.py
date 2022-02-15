###
#
# Lenovo Redfish examples - Patch specified uri with specified body
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
import json
import redfish
import traceback
import lenovo_utils as utils


def raw_command_patch(ip, login_account, login_password, resource_uri, body):
    """Patch specified resource
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params resource_uri: redfish resource uri
    :type resource_uri: string
    :params body: json string body for redfish patch request
    :type body: string
    :returns: returns specified resource information when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    request_url = resource_uri

    headers = {"If-Match": "*"}
    response_url = REDFISH_OBJ.patch(request_url, body=json.loads(body), headers=headers)
    if response_url.status not in [200, 204]:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    message_extendedinfo = ""
    if response_url.status == 200 and "@Message.ExtendedInfo" in response_url.dict:
        message_extendedinfo = "@Message.ExtendedInfo: " + str(response_url.dict["@Message.ExtendedInfo"])

    result['ret'] = True
    result['msg'] = "Update resource uri %s successfully. %s" %(resource_uri, message_extendedinfo)
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_helpmessage(parser):
    parser.add_argument('--resource_uri', type=str, required=True,
            help='Specify redfish resource uri. Ex: "/redfish/v1/Systems/1"')
    parser.add_argument('--body', type=str, required=True,
            help='Specify json string body for redfish patch request. Ex: "{\\"AssetTag\\": \\"new_asset_tag\\"}"')


def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["resource_uri"] = args.resource_uri
    parameter_info["body"] = args.body
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get resource_uri and body
    resource_uri = parameter_info["resource_uri"]
    body = parameter_info["body"]

    # Patch redfish resource with body and check result
    result = raw_command_patch(ip, login_account, login_password, resource_uri, body)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

