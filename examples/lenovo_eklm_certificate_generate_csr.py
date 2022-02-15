###
#
# Lenovo Redfish examples - generate ExternalKeyLifecycleManager(EKLM) client certificate CSR
# SecureKeyLifecycleManager feature uses centralized EKLM server to provide keys that unlock storage hardware.
# To use this feature, below steps are needed:
#  - Ensure required license has been imported in BMC(XCC)
#  - Configure EKLM Server(s) in BMC(XCC)
#  - Install/import EKLM server certificate in BMC(XCC) which can be downloaded from EKLM server
#  - Generate EKLM client certificate CSR in BMC(XCC)
#  - Sign the CSR with the CA certificate in EKLM server
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
import traceback
import lenovo_utils as utils


def lenovo_eklm_certificate_generate_csr(ip, login_account, login_password, Country, StateOrProvince, Locality, Organization, HostName):
    """ Generate EKLM client certificate CSR
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params Country: Country Name for CSR
        :type Country: string
        :params StateOrProvince: State or Province Name for CSR
        :type StateOrProvince: string
        :params Locality: City or Locality Name for CSR
        :type Locality: string
        :params Organization: Organization Name for CSR
        :type Organization: string
        :params HostName: Host Name for CSR
        :type HostName: string
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
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
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
 
        # Access /redfish/v1/Managers/1 to check whether SecureKeyLifecycleService is supported or not
        eklm_url = None
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
                eklm_url = response_url.dict['Oem']['Lenovo']['SecureKeyLifecycleService']['@odata.id']
                break

        # Return here when EKLM feature is not supported
        if eklm_url is None:
            result = {'ret': False, 'msg': 'ExternalKeyLifecycleManager(EKLM) is not supported.'}
            REDFISH_OBJ.logout()
            return result

        # Use standard API /redfish/v1/CertificateService/CertificateLocations
        if 'CertificateService' in response_base_url.dict:
            request_url = response_base_url.dict['CertificateService']['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                return result
            if 'Actions' in response_url.dict and '#CertificateService.GenerateCSR' in response_url.dict['Actions']:
                target_url = response_url.dict['Actions']['#CertificateService.GenerateCSR']['target']
                request_body = {'CertificateCollection':{'@odata.id':'/redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService/ClientCertificate'}}
                request_body['KeyUsage'] = ['DigitalSignature']
                request_body['Country'] = Country
                request_body['City'] = Locality
                request_body['CommonName'] = HostName
                request_body['State'] = StateOrProvince
                request_body['Organization'] = Organization
                ### Extended settings examples begin ###
                ## If you want to set optional information, please use below properties to set.
                #request_body["AlternativeNames"] = ["Alternative Name"]
                #request_body["ChallengePassword"] = "ChallengePassword"
                #request_body["ContactPerson"] = "Your contact person name"
                #request_body["Email"] = "Email address"
                #request_body["OrganizationalUnit"] = "Organizational Unit Name"
                #request_body["Surname"] = "Surname"
                #request_body["GivenName"] = "Given Name"
                #request_body["Initials"] = "Initials"
                #request_body["KeyCurveId"] = "KeyCurveId"
                #request_body["KeyPairAlgorithm"] = "KeyPairAlgorithm"
                #request_body["UnstructuredName"] = "UnstructuredName"
                ### Extended settings examples end ###

                # Perform action #CertificateService.GenerateCSR
                response_url = REDFISH_OBJ.post(target_url, body=request_body)
                if response_url.status not in [200, 201, 202, 204]:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        target_url, response_url.status, error_message)}
                    return result
                # Save received csr string
                filename = 'generated_' + HostName + '_eklm_client_certificate' + '.csr'
                if os.path.exists(filename):
                    os.remove(filename)
                if 'CSRString' in response_url.dict:
                    with open(filename, 'w') as f:
                        f.write(response_url.dict['CSRString'])

                result = {'ret': True,
                          'msg':"The CSR for EKLM client certificate has been generated successfully. Format is PEM. (%s)" %(filename)}
                return result

        # No CertificateService resource found
        result = {'ret': False, 'msg': 'CertificateService is not supported'}
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
    parser.add_argument('--Country', type=str, required=True, 
                         help='The Country name for required certificate information. (e.g. CN, US, JP, AU)')
    parser.add_argument('--StateOrProvince', type=str, required=True, 
                         help='The State or Province name for required certificate information.')
    parser.add_argument('--Locality', type=str, required=True, 
                         help='The City or Locality name for required certificate information.')
    parser.add_argument('--Organization', type=str, required=True, 
                         help='The Organization name for required certificate information.')
    parser.add_argument('--HostName', type=str, required=True, 
                         help='The BMC Host name or IP for required certificate information. (e.g. KMIPuser)')
 

def add_parameter():
    """Add parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["Country"] = args.Country
    parameter_info["StateOrProvince"] = args.StateOrProvince
    parameter_info["Locality"] = args.Locality
    parameter_info["Organization"] = args.Organization
    parameter_info["HostName"] = args.HostName
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    Country = parameter_info["Country"]
    StateOrProvince = parameter_info["StateOrProvince"]
    Locality = parameter_info["Locality"]
    Organization = parameter_info["Organization"]
    HostName = parameter_info["HostName"]

    # Generate EKLM client certificate CSR and check result
    result = lenovo_eklm_certificate_generate_csr(ip, login_account, login_password, Country, StateOrProvince, Locality, Organization, HostName)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

