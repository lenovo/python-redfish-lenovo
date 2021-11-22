###
#
# Lenovo Redfish examples - import HTTPS file server certificate to update firmware of BMC.
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


def lenovo_https_certificate_import(ip, login_account, login_password, certfile):
    """ Import ssl certificate
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params certfile: certificate file by user specified
    :type certfile: string
    :returns: returns successful result when succeeded or error message when failed
    """

    result = {}

    # check file existing and readable
    if certfile and not os.access(certfile, os.R_OK):
        result = {'ret': False,
                  'msg': "Specified file %s does not exist or can't be accessed. Please check your certificate file path." % (
                      certfile)}
        return result

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
            # Set request body
            request_body = {'CertificateType': 'PEM'}
            request_body['CertificateString'] = read_cert_file_pem(certfile)
            if request_body['CertificateString'] is None:
                result = {'ret': False,
                          'msg': "Target server required certificate format should be PEM. Please specify correct certificate file."}
                return result

            # Get https certificate uri to set request body
            request_upload_url = response_update_service_url.dict["RemoteServerCertificates"]["@odata.id"]
            # Upload file server certificate
            response_upload_url = REDFISH_OBJ.post(request_upload_url, body=request_body)
            if response_upload_url.status == 201:
                result = {'ret':True,
                          'msg':"Upload certificate successfully. The file server certificate has been uploaded to '%s'." % (
                              response_upload_url.dict['@odata.id'])}
                return result
            elif response_upload_url.status == 409:
                result = {"ret": False,
                          "msg": "Failed to upload certificate. The current number of certificates in the target certificate collection already reached the maximum number:4."}
                return result
            else:
                message = utils.get_extended_error(response_upload_url)
                result = {'ret': False,
                          'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                              request_upload_url, response_upload_url.status, message)}
                return result
        else:
            result = {'ret': False,
                      'msg': "Target server does not support uploading certificate file."}
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



def read_cert_file_pem(cert):
    fhandle = None
    try:
        fhandle = open(cert, 'r')
        filecontent = fhandle.read()
    except:
        filecontent = ''
    finally:
        if fhandle:
            fhandle.close()
    return filecontent if '-----BEGIN CERTIFICATE-----' in filecontent else None


def add_helpmessage(parser):
    parser.add_argument('--certfile', type=str, required=True, help="An file that contains signed certificate in PEM format. Note: SR635/SR655 does not support uploading HTTPS certificate.")


def add_parameter():
    """Add parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["certfile"] = args.certfile
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    certfile = parameter_info["certfile"]

    # Import certificate and check result
    result = lenovo_https_certificate_import(ip, login_account, login_password, certfile)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
