###
#
# Lenovo Redfish examples - get manager external account provider LDAP information
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

import sys
import redfish
import json
import lenovo_utils as utils


def lenovo_get_bmc_external_ldap(ip, login_account, login_password):
    """ Get manager LDAP user information
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns get manager LDAP user information result when succeeded or error message when failed
        """

    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        # Get response_base_url
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status != 200:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        # Use standard API for LDAP in AccountService first
        accounts_url = response_base_url.dict['AccountService']['@odata.id']
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status != 200:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                accounts_url, response_accounts_url.status, error_message)}
            return result

        ldap_client_info = {}
        if "LDAP" in response_accounts_url.dict and response_accounts_url.dict["LDAP"] and "LDAPService" in response_accounts_url.dict["LDAP"]:
            properties = ['LDAPService', 'ServiceEnabled', 'ServiceAddresses', 'Authentication']
            for property in properties:
                if property in response_accounts_url.dict["LDAP"]:
                    ldap_client_info[property] = response_accounts_url.dict["LDAP"][property]
                else:
                    ldap_client_info[property] = None
            result = {'ret': True, 'msg': ldap_client_info}
            return result

        # Use Oem API /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient if standard API not present
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
            # Access /redfish/v1/Managers/1/NetworkProtocol
            if "NetworkProtocol" not in response_url.dict:
                continue
            network_protocol_url = response_url.dict["NetworkProtocol"]['@odata.id']
            response_network_protocol_url = REDFISH_OBJ.get(network_protocol_url, None)
            if response_network_protocol_url.status != 200:
                error_message = utils.get_extended_error(response_network_protocol_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    network_protocol_url, response_network_protocol_url.status, error_message)}
                return result
            # Access /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient
            if "Oem" not in response_network_protocol_url.dict:
                continue
            if response_network_protocol_url.dict["Oem"] and "Lenovo" in response_network_protocol_url.dict["Oem"]:
                if "LDAPClient" in response_network_protocol_url.dict["Oem"]["Lenovo"]:
                    ldap_client_uri = response_network_protocol_url.dict["Oem"]["Lenovo"]["LDAPClient"]["@odata.id"]
                    response_ldap_client = REDFISH_OBJ.get(ldap_client_uri, None)
                    if response_ldap_client.status == 200:
                        ldap_client_info = map_oem2standard_property(response_ldap_client.dict)
                        result = {'ret': True, 'msg': ldap_client_info}
                        return result
                    else:
                        error_message = utils.get_extended_error(response_ldap_client)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            ldap_client_uri, response_ldap_client.status, error_message)}
                        return result

        # No LDAP resource found
        result = {'ret': False, 'msg': 'LDAP is not supported'}
        return result

    except Exception as e:
        result = {'ret': False, 'msg': 'exception msg %s' % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def map_oem2standard_property(oem_response_dict):
    standard_ldap_info = {}
    standard_ldap_info['Authentication'] = {'AuthenticationType': 'UsernameAndPassword'}
    standard_ldap_info['LDAPService'] = {'SearchSettings': {}}
    standard_ldap_info['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = list()
    if 'RootDN' in oem_response_dict:
        standard_ldap_info['LDAPService']['SearchSettings']['BaseDistinguishedNames'].append(oem_response_dict['RootDN'])
    if 'GroupSearchAttribute' in oem_response_dict:
        standard_ldap_info['LDAPService']['SearchSettings']['GroupNameAttribute'] = oem_response_dict['GroupSearchAttribute']
    if 'GroupFilter' in oem_response_dict:
        standard_ldap_info['LDAPService']['SearchSettings']['GroupsAttribute'] = oem_response_dict['GroupFilter']
    if 'UIDSearchAttribute' in oem_response_dict:
        standard_ldap_info['LDAPService']['SearchSettings']['UsernameAttribute'] = oem_response_dict['UIDSearchAttribute']
    standard_ldap_info['ServiceAddresses'] = list()
    if 'LDAPServers' in oem_response_dict:
        ldapdict = oem_response_dict['LDAPServers']
        for server in ['Server1', 'Server2', 'Server3', 'Server4']:
            if ldapdict[server + 'HostName_IPAddress']:
                serviceaddr = '%s:%s' %(ldapdict[server + 'HostName_IPAddress'], ldapdict[server + 'Port'])
            else:
                serviceaddr = ':%s' %(ldapdict[server + 'Port'])
            standard_ldap_info['ServiceAddresses'].append(serviceaddr)
    if 'ProtocolEnabled' in oem_response_dict and not oem_response_dict['ProtocolEnabled']:
        standard_ldap_info['ServiceEnabled'] = False
    else:
        standard_ldap_info['ServiceEnabled'] = True
    return standard_ldap_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get ldap information and check result
    result = lenovo_get_bmc_external_ldap(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

