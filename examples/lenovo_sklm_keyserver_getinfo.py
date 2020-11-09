###
#
# Lenovo Redfish examples - get SKLM key server info
# SecureKeyLifecycleManager feature uses centralized SKLM server to provide keys that unlock storage hardware.
# To use this feature, below steps are needed:
#  - Ensure required license has been imported in BMC(XCC)
#  - Configure SKLM Server(s) in BMC(XCC)
#  - Install/import SKLM server certificate in BMC(XCC) which can be downloaded from SKLM server
#  - Generate SKLM client certificate CSR in BMC(XCC)
#  - Sign the CSR with the CA certificate in SKLM server
#  - Import the signed client certificate in BMC(XCC)
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
import lenovo_utils as utils


def lenovo_sklm_keyserver_getinfo(ip, login_account, login_password):
    """ Get SKLM key server info
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns key server info when succeeded or error message when failed
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get /redfish/v1
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    if response_base_url.status != 200:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            '/redfish/v1', response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get /redfish/v1/Managers
    managers_url = response_base_url.dict['Managers']['@odata.id']
    response_managers_url = REDFISH_OBJ.get(managers_url, None)
    if response_managers_url.status != 200:
        error_message = utils.get_extended_error(response_managers_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            managers_url, response_managers_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Access /redfish/v1/Managers/1 to get SecureKeyLifecycleService url
    sklm_url = None
    for request in response_managers_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        if 'SecureKeyLifecycleService' in str(response_url.dict):
            sklm_url = response_url.dict['Oem']['Lenovo']['SecureKeyLifecycleService']['@odata.id']
            break

    # Return here when SKLM feature is not supported
    if sklm_url is None:
        result = {'ret': False, 'msg': 'SecureKeyLifecycleManager(SKLM) is not supported.'}
        REDFISH_OBJ.logout()
        return result

    # Get common info from /redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService
    sklm_details = {}
    request_url = sklm_url
    response_url = REDFISH_OBJ.get(request_url, None)
    if response_url.status != 200:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result
    for property in ['Name', 'KeyRepoServers', 'DeviceGroup', 'Protocol']:
        if property in response_url.dict:
            sklm_details[property] = response_url.dict[property]

    # Get server certificate info from /redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService/ServerCertificate/1
    sklm_details['ServerCertificate'] = {}
    request_url = sklm_url + '/ServerCertificate/1'
    response_url = REDFISH_OBJ.get(request_url, None)
    if response_url.status == 200:
        for property in ['ValidNotBefore', 'ValidNotAfter', 'CertificateType', 'Subject',
                         'Issuer', 'KeyUsage', 'CertificateString']:
            if property in response_url.dict:
                sklm_details['ServerCertificate'][property] = response_url.dict[property]

    # Get client certificate info from /redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService/ClientCertificate/1
    sklm_details['ClientCertificate'] = {}
    request_url = sklm_url + '/ClientCertificate/1'
    response_url = REDFISH_OBJ.get(request_url, None)
    if response_url.status == 200:
        for property in ['ValidNotBefore', 'ValidNotAfter', 'CertificateType', 'Subject',
                         'Issuer', 'KeyUsage', 'CertificateString']:
            if property in response_url.dict:
                sklm_details['ClientCertificate'][property] = response_url.dict[property]

    result['ret'] = True
    result['entries'] = sklm_details
    REDFISH_OBJ.logout()
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

    # Get SKLM key server info and check result
    result = lenovo_sklm_keyserver_getinfo(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

