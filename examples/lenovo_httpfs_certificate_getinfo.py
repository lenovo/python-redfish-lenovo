###
#
# Lenovo Redfish examples - Get HTTPS certificate info
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


def lenovo_httpfs_certificate_getinfo(ip, login_account, login_password):
    """ Get HTTPS certificate info
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
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
        # Check /redfish/v1/UpdateService/RemoteServerCertificates existing
        if "RemoteServerCertificates" in response_update_service_url.dict:
            remote_cert_url = response_update_service_url.dict["RemoteServerCertificates"]["@odata.id"]
            response_remote_cert = REDFISH_OBJ.get(remote_cert_url, None)
            if response_remote_cert.status != 200:
                message = utils.get_extended_error(response_remote_cert)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                    remote_cert_url, response_remote_cert.status, message)}
                return result
            if "Members" in response_remote_cert.dict:
                all_certs = []
                for member in response_remote_cert.dict["Members"]:
                    request_get_url = member["@odata.id"]
                    response_get_url = REDFISH_OBJ.get(request_get_url, None)
                    if response_get_url.status == 200:
                        cert_info = {}
                        for property in ['ValidNotAfter', 'ValidNotBefore', 'KeyUsage', 'CertificateType',
                                         'Subject', 'CertificateString', 'Issuer', 'Id', '@odata.id']:
                            if property in response_get_url.dict:
                                cert_info[property] = response_get_url.dict[property]
                        all_certs.append(cert_info)
                    else:
                        message = utils.get_extended_error(response_get_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            request_get_url, response_get_url.status, message)}
                        return result

                result = {'ret': True, 'entries': all_certs}
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


def add_parameter():
    """Add parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get HTTPS certificate info and check result
    result = lenovo_httpfs_certificate_getinfo(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
