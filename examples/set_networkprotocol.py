###
#
# Lenovo Redfish examples - Set BMC service port
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
import traceback

def set_networkprotocol(ip, login_account, login_password, service, enabled, port):
    """This feature provides abilities to enable or disable a BMC service and to change port numbers
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params service: Specify service information supported by BMC. Support:["HTTPS","SSDP","SSH","SNMP","IPMI","VirtualMedia"]
        :type service: string
        :params enabled: Disable(0) or enable(1) the BMC service
        :type enabled: int
        :params port: The value of this property shall contain the port assigned for the protocol
        :type port: int
        :returns: returns Get bmc ntp result when succeeded or error message when failed
        """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status == 200:
            for request in response_managers_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                #Get Network Protocol url from the manager url response
                if response_url.status == 200:
                    network_protocol_url = response_url.dict["NetworkProtocol"]['@odata.id']
                else:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    return result

                # get etag to set If-Match precondition
                response_network_protocol_url = REDFISH_OBJ.get(network_protocol_url, None)
                if response_network_protocol_url.status != 200:
                    error_message = utils.get_extended_error(response_network_protocol_url)
                    result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                        network_protocol_url, response_network_protocol_url.status, error_message)}
                    return result
                if "@odata.etag" in response_network_protocol_url.dict:
                    etag = response_network_protocol_url.dict['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}


                # Build request body for modify network protocol
                if service in ["IPMI", "SSDP"]:
                    body = {service:{"ProtocolEnabled":bool(int(enabled))}}
                elif service in ["SSH", "HTTPS", "SNMP", "VirtualMedia"]:
                    body = {service:{"ProtocolEnabled":bool(int(enabled)),"Port":port}}
                else:
                    result = {'ret': False, 'msg': "Please check the BMC service name is in the [HTTPS,HTTP,SSDP,SSH,SNMP,IPMI,VirtualMedia]"}
                    return result

                # Send Patch Request to Modify Network Port
                response_network_protocol_url = REDFISH_OBJ.patch(network_protocol_url, body=body, headers=headers)
                if response_network_protocol_url.status in [200,204]:
                    result = {'ret': True,
                              'msg': "Set BMC service %s successfully" %service}
                    return result
                else:
                    error_message = utils.get_extended_error(response_network_protocol_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        network_protocol_url, response_network_protocol_url.status, error_message)}
                    return result

        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                managers_url, response_managers_url.status, error_message)}
            return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': 'exception msg %s' % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_helpmessage(parser):
    parser.add_argument('--service', type=str, choices=["HTTPS","SSDP","SSH","SNMP","IPMI","VirtualMedia"], required=True,
                        help='Specify service information supported by BMC. Support:["HTTPS","SSDP","SSH","SNMP","IPMI","VirtualMedia"]')
    parser.add_argument('--enabled', type=int, default=1,choices=[0, 1], help='Disable(0) or enable(1) the BMC service. default is 1')
    parser.add_argument('--port', type=int, help='The value of this property shall contain the port assigned for the protocol.'
                                                 'These ports "IPMI:623","SLP:427" and "SSDP:1900" are reserved and can only be used for the corresponding services.')


def add_parameter():
    """Add set network protocol parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    if args.service is not None:
        parameter_info["service"] = args.service
    parameter_info["enabled"] = args.enabled
    parameter_info["port"] = args.port
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
        service = parameter_info["service"]
        enabled = parameter_info["enabled"]
        port = parameter_info["port"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # set service port and check result
    result = set_networkprotocol(ip, login_account, login_password,service, enabled, port)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
