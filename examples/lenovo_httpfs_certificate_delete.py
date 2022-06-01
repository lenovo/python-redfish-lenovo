###
#
# Lenovo Redfish examples - delete HTTPS file server certificate
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

import sys, os
import redfish
import json
import traceback
import lenovo_utils as utils


def lenovo_httpfs_certificate_delete(ip, login_account, login_password, cert_id):
    """ Delete HTTPS certificate
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params cert_id: certificate id
    :type cert_id: int
    :returns: returns successful result when succeeded or error message when failed
    """

    result = {}

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get response_base_url
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status != 200:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ('/redfish/v1', response_base_url.status, error_message)}
            return result

        update_service_url = response_base_url.dict['UpdateService']['@odata.id']
        response_update_service_url = REDFISH_OBJ.get(update_service_url, None)
        if response_update_service_url.status != 200:
            message = utils.get_extended_error(response_update_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                update_service_url, response_update_service_url.status, message)}
            return result
        if "RemoteServerCertificates" in response_update_service_url.dict:
            remote_cert_url = response_update_service_url.dict["RemoteServerCertificates"]["@odata.id"]
            response_remote_cert = REDFISH_OBJ.get(remote_cert_url, None)
            if response_remote_cert.status != 200:
                message = utils.get_extended_error(response_remote_cert)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                    remote_cert_url, response_remote_cert.status, message)}
                return result

            request_delete_url = remote_cert_url + "/" + str(cert_id)
            if "Members" in response_remote_cert.dict and "Members@odata.count" in response_remote_cert.dict:
                if response_remote_cert.dict["Members@odata.count"] <= 0:
                    result = {'ret': False,
                              'msg': "No HTTPS certificates present, no need to delete."}
                    return result
                for member in response_remote_cert.dict["Members"]:
                    if request_delete_url == member["@odata.id"]:
                        response_delete_url = REDFISH_OBJ.delete(request_delete_url, None)
                        if response_delete_url.status == 204:
                            result = {'ret': True,'msg': "Delete certificate successfully."}
                            return result
                        else:
                            message = utils.get_extended_error(response_delete_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                request_delete_url, response_delete_url.status, message)}
                            return result
                result = {'ret': False,
                          'msg': "Failed to delete the certificate. The specified certificate does not exist."}
                return result

        # No HTTPS certificate resource found
        result = {'ret': False, 'msg': "HTTPS certificate is not supported."}
        return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def add_helpmessage(parser):
    parser.add_argument('--cert_id', type=int, required=True, help="Specify the certificate ID.")


def add_parameter():
    """Add parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["cert_id"] = args.cert_id
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    cert_id = parameter_info["cert_id"]

    # Delete certificate and check result
    result = lenovo_httpfs_certificate_delete(ip, login_account, login_password, cert_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
