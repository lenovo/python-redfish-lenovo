###
#
# Lenovo Redfish examples - Set BMC ntp
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
import traceback
import lenovo_utils as utils


def set_bmc_ntp(ip, login_account, login_password, ntp_server, ProtocolEnabled):
    """Set BMC ntp server
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params ntp_server: ntp_server by user specified
    :type ntp_server: list
    :params ProtocolEnabled: ProtocolEnabled by user specified
    :type ProtocolEnabled: string
    :returns: returns set manager ntp result when succeeded or error message when failed
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
    try:
        # Get ServiceBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            manager_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response error code %s \nerror_message: %s" % (
                response_base_url.status, error_message)}
            return result

        # Get the manager url response resource
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        if response_manager_url.status == 200:
            for request in response_manager_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200:
                    network_url = response_url.dict['NetworkProtocol']['@odata.id']
                    if len(ntp_server) > 4:
                        result = {'ret': False, 'msg': "User can specify the name of up to 4 NTP servers."}
                        return result

                    # get etag to set If-Match precondition
                    response_network_url = REDFISH_OBJ.get(network_url, None)
                    if response_network_url.status != 200:
                        error_message = utils.get_extended_error(response_network_url)
                        result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                            network_url, response_network_url.status, error_message)}
                        return result
                    if "@odata.etag" in response_network_url.dict:
                        etag = response_network_url.dict['@odata.etag']
                    else:
                        etag = ""
                    headers = {"If-Match": etag}

                    # Build patch body for request set ntp servers
                    Protocol = {"NTPServers":ntp_server,"ProtocolEnabled":  bool(int(ProtocolEnabled))}
                    parameter = {"NTP": Protocol}
                    response_network_url = REDFISH_OBJ.patch(network_url, body=parameter, headers=headers)
                    if response_network_url.status in [200,204]:
                        result = {'ret': True, 'msg': "Set BMC ntp servers successfully"}
                    else:
                        error_message = utils.get_extended_error(response_network_url)
                        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                            network_url, response_network_url.status, error_message)}
                        return result
                else:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    return result

        else:
            error_message = utils.get_extended_error(response_manager_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                manager_url, response_manager_url.status, error_message)}
            return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error message %s" % e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def add_helpmessage(argget):
    argget.add_argument('--ntpserver', nargs="*", type=str, required=True, help="Specify the names of  NTP servers, up to 4 NTP servers can be used. use space to seperate them. example: event1 event2.")
    argget.add_argument('--enabled', type=str, choices = ["0", "1"], required=True, help='Indicates if the NTP protocol is enabled or disabled. (0:false, 1:true)')


def add_parameter():
    """Add set manager ntp parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["ProtocolEnabled"] = args.enabled
    parameter_info["ntp_server"] = args.ntpserver
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
        ntp_server = parameter_info['ntp_server']
        ProtocolEnabled = parameter_info['ProtocolEnabled']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set manager ntp result and check result
    result = set_bmc_ntp(ip, login_account, login_password, ntp_server, ProtocolEnabled)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
