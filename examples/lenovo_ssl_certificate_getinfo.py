###
#
# Lenovo Redfish examples - Get ssl certificate info
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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


def lenovo_ssl_certificate_getinfo(ip, login_account, login_password):
    """ Get ssl certificate info
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns ssl certificate info when succeeded or error message when failed
        """

    result = {}

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
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
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        # Use standard API /redfish/v1/CertificateService/CertificateLocations first
        if 'CertificateService' in response_base_url.dict:
            request_url = response_base_url.dict['CertificateService']['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                return result
            if 'CertificateLocations' in response_url.dict:
                request_url = response_url.dict['CertificateLocations']['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status != 200:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    return result
                ssl_cert_info = {}
                if 'Links' in response_url.dict and 'Certificates' in response_url.dict['Links']:
                    cert_collection = response_url.dict['Links']['Certificates']
                    for certitem in cert_collection:
                        cert_url = certitem['@odata.id']
                        if 'HTTPS' not in cert_url:
                            continue
                        request_url = cert_url
                        response_url = REDFISH_OBJ.get(request_url, None)
                        if response_url.status != 200:
                            error_message = utils.get_extended_error(response_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                request_url, response_url.status, error_message)}
                            return result
                        for property in ['ValidNotAfter', 'ValidNotBefore', 'KeyUsage', 'CertificateType',
                                             'Subject', 'CertificateString', 'Issuer']:
                            if property in response_url.dict:
                                ssl_cert_info[property] = response_url.dict[property]
                        break
                result['ret'] = True
                result['entries'] = ssl_cert_info
                return result

        # Use Oem API /redfish/v1/Managers/1/Oem/Lenovo/Security
        managers_url = response_base_url.dict['Managers']['@odata.id']
        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status != 200:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                managers_url, response_managers_url.status, error_message)}
            return result
        for request in response_managers_url.dict['Members']:
            # Access /redfish/v1/Managers/1
            request_url = request['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                return result

            # Check /redfish/v1/Managers/1/Oem/Lenovo/Security existing
            if "Oem" not in response_url.dict:
                continue
            if "Lenovo" not in response_url.dict["Oem"]:
                continue
            if "Security" not in response_url.dict["Oem"]["Lenovo"]:
                continue
            if "@odata.id" not in response_url.dict["Oem"]["Lenovo"]["Security"]:
                continue

            # Access /redfish/v1/Managers/1/Oem/Lenovo/Security
            security_url = response_url.dict["Oem"]["Lenovo"]["Security"]['@odata.id']
            response_security_url = REDFISH_OBJ.get(security_url, None)
            if response_security_url.status != 200:
                error_message = utils.get_extended_error(response_security_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    security_url, response_security_url.status, error_message)}
                return result
            if "PublicKeyCertificates" not in response_security_url.dict:
                continue
            ssl_cert_info = {"EnableHttps": True, "PublicKeyCertificates":{}, "CertificateSigningRequests":{}}
            if "SSLSettings" in  response_security_url.dict and "EnableHttps" in response_security_url.dict["SSLSettings"]:
                ssl_cert_info["EnableHttps"] = response_security_url.dict["SSLSettings"]["EnableHttps"]
            for cert in response_security_url.dict["PublicKeyCertificates"]:
                if 'Subject' in cert and cert['Subject'] == 'Server_Cert':
                    for property in ['Subject', 'AltSubject', 'Expire', 'PublicKey']:
                        if property in cert:
                            ssl_cert_info["PublicKeyCertificates"][property] = cert[property]
                        else:
                            ssl_cert_info["PublicKeyCertificates"][property] = None
            if "CertificateSigningRequests" in response_security_url.dict:
                for certcsr in response_security_url.dict["CertificateSigningRequests"]:
                    for property in ['Subject', 'AltSubject', 'UnstructuredName', 'ChallengePassword']:
                        if property in certcsr:
                            ssl_cert_info["CertificateSigningRequests"][property] = certcsr[property]
                        else:
                            ssl_cert_info["CertificateSigningRequests"][property] = None

            result['ret'] = True
            result['entries'] = ssl_cert_info
            return result

        # No SSL certificate resource found
        result = {'ret': False, 'msg': 'SSL certificate is not supported'}
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

    # Get ssl certificate info and check result
    result = lenovo_ssl_certificate_getinfo(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

