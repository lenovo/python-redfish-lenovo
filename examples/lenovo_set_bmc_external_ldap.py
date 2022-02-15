###
#
# Lenovo Redfish examples - set manager LDAP server
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
import redfish
import json
import traceback
import lenovo_utils as utils


def lenovo_set_bmc_external_ldap(ip, login_account, login_password, ldapserver, client_distinguished_name, client_password,
                           rootdn, uid_search_attribute, group_filter, group_search_attribute):
    """ Set manager LDAP information
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params ldapserver: If you choose the pre-configured option, at least one server must be configured
        :type ldapserver: string
        :params clientdn: Specify the Client Distinguished Name(DN) to be used for the initial bind. Note that LDAP Binding Method must be set to "Configured"
        :type clientdn: string
        :params clientpwd: Note that LDAP Binding Method must be set to "Configured"
        :type clientpwd: string
        :params rootdn: BMC uses the "ROOT DN" field in Distinguished Name format as root entry of directory tree.This DN will be used as the base object for all searches.
        :type rootdn: string
        :params uid_search_attribute: This search request must specify the attribute name used to represent user IDs on that server
        :type uid_search_attribute: string
        :params group_filter: This field is used for group authentication, limited to 511 characters, and consists of one or more group names
        :type group_filter: string
        :params group_search_attribute: This field is used by the search algorithm to find group membership infomation for a specific user
        :type group_search_attribute: string
        :returns: returns set manager LDAP user information result when succeeded or error message when failed
        """

    # Check user specified parameter
    result = check_parameter(ldapserver, client_distinguished_name, client_password)
    if result["ret"] is False:
        return result

    login_host = "https://" + ip
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        traceback.print_exc()
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

        flag_try_standard_api_first = True
        if flag_try_standard_api_first:
            # Use standard API for LDAP in AccountService first
            accounts_url = response_base_url.dict['AccountService']['@odata.id']
            response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
            if response_accounts_url.status != 200:
                error_message = utils.get_extended_error(response_accounts_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                    accounts_url, response_accounts_url.status, error_message)}
                return result

            # Set for SR635/SR655 using standard API with some oem properties
            if "Oem" in response_accounts_url.dict and "Ami" in response_accounts_url.dict["Oem"]:
                try:
                    encryption_type = response_accounts_url.dict['LDAP']['Authentication']['Oem']['Ami']['EncryptionType']
                except:
                    encryption_type = "NoEncryption"
                # Build request body for set ldap server
                body = {'ServiceEnabled': True} # Enable the LDAP service for user to use
                if client_distinguished_name is not None:
                    body['Authentication'] = {'Username': client_distinguished_name, 'Password': client_password, 'Oem': {'Ami': {}}}
                    body['Authentication']['Oem']['Ami'] = {'BindingMethod': 'PreConfiguredCredential', 'EncryptionType': encryption_type, 'CommonNameType': 'IPAddress'}
                else:
                    body['Authentication'] = {'Oem': {'Ami': {'BindingMethod': 'LoginCredential', 'EncryptionType': encryption_type, 'CommonNameType': 'IPAddress'}}}
                body['LDAPService'] = {'SearchSettings': {}}
                body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = [rootdn]
                body['LDAPService']['SearchSettings']['GroupsAttribute'] = uid_search_attribute
                body['ServiceAddresses'] = list()
                (serverlist, portlist) = parse_ldapserver(ldapserver)
                for i in range(len(serverlist)):
                    server_info = "%s:%s" %(serverlist[i], portlist[i])
                    body['ServiceAddresses'].append(server_info)
 
                # Patch the new LDAP setting
                ldap_client_uri = accounts_url
                request_body = {'LDAP': body}
                headers = {"If-Match": "*"}
                response_ldap_client = REDFISH_OBJ.patch(ldap_client_uri, body=request_body, headers=headers)
                if response_ldap_client.status in [200, 204]:
                    result =  {"ret": True, "msg":"Ldap server was successfully configured"}
                    return result
                else:
                    error_message = utils.get_extended_error(response_ldap_client)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        ldap_client_uri, response_ldap_client.status, error_message)}
                    return result

            # Set for servers except SR635/SR655
            if "LDAP" in response_accounts_url.dict and response_accounts_url.dict["LDAP"] and "LDAPService" in response_accounts_url.dict["LDAP"]:
                # Build request body for set ldap server
                body = {'ServiceEnabled': True} # Enable the LDAP service for user to use
                if client_distinguished_name is not None:
                    body['Authentication'] = {'AuthenticationType': 'UsernameAndPassword', 'Username': client_distinguished_name, 'Password': client_password}
                body['LDAPService'] = {'SearchSettings': {}}
                body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = [rootdn]
                body['LDAPService']['SearchSettings']['GroupsAttribute'] = group_filter
                body['LDAPService']['SearchSettings']['GroupNameAttribute'] = group_search_attribute
                body['LDAPService']['SearchSettings']['UsernameAttribute'] = uid_search_attribute
                body['ServiceAddresses'] = list()
                (serverlist, portlist) = parse_ldapserver(ldapserver)
                for i in range(len(serverlist)):
                    server_info = "%s:%s" %(serverlist[i], portlist[i])
                    body['ServiceAddresses'].append(server_info)
 
                # Patch the new LDAP setting
                ldap_client_uri = accounts_url
                request_body = {'LDAP': body}
                headers = {"If-Match": "*"}
                response_ldap_client = REDFISH_OBJ.patch(ldap_client_uri, body=request_body, headers=headers)
                if response_ldap_client.status in [200, 204]:
                    result =  {"ret": True, "msg":"Ldap server was successfully configured"}
                    return result
                else:
                    error_message = utils.get_extended_error(response_ldap_client)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        ldap_client_uri, response_ldap_client.status, error_message)}
                    return result

        # Use Oem API /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient
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
                    # Build request body for set ldap server
                    body = {}
                    if client_distinguished_name is None or client_distinguished_name == '':
                        binding_method = 'Anonymously'
                    else:
                        binding_method = 'Configured'
                    body["BindingMethod"] = {"ClientPassword":client_password,"ClientDN":client_distinguished_name, "Method":binding_method}
                    body["RootDN"] = rootdn
                    body["GroupFilter"] = group_filter
                    body["GroupSearchAttribute"] = group_search_attribute
                    body["UIDSearchAttribute"] = uid_search_attribute
                    server_info = {}
                    server_info["Method"] = "Pre_Configured"
                    (serverlist, portlist) = parse_ldapserver(ldapserver)
                    for i in range(len(serverlist)):
                        server_info["Server"+ str(i+1) +"HostName_IPAddress"] = serverlist[i]
                        server_info["Server" + str(i+1) + "Port"] = portlist[i]
                    body["LDAPServers"] = server_info
      
                    ### Extended settings examples begin ###
                    ## Use LoginPermissionAttribute property to set the permission attribute for user that successfully authenticates via a LDAP server.
                    #body["LoginPermissionAttribute"] = "IBMRBSPermissions=010000000000" #Supervisor Access
                    ## or
                    #body["LoginPermissionAttribute"] = "IBMRBSPermissions=001000000000" #Read Only Access
                    ## Use Authorization property to set authorization mode
                    #body["Authorization"] = "LDAPServer" #use LDAP server for authentication and authorization
                    ## or
                    #body["Authorization"] = "Locally" #use LDAP server for authentication only(without authorization). This mode is only supported in an Active Directory environment.
                    ## Use ActiveDirectory property to enable enhanced role-based security for Active Directory Users
                    #body["ActiveDirectory"] = {"ServerTargetName": "YourServerName", "RoleBasedSecurity": True}
                    ### Extended settings examples end ###
      
                    # Patch the new LDAP setting
                    request_body = body
                    response_ldap_client = REDFISH_OBJ.patch(ldap_client_uri, body=request_body)
                    if response_ldap_client.status in [200, 204]:
                        result =  {"ret": True, "msg":"Ldap server was successfully configured"}
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
        traceback.print_exc()
        result = {'ret': False, 'msg': 'exception msg %s' % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def check_parameter(ldapserver, client_name, client_pwd):
    if client_name is not None and client_pwd is None:
        result = {"ret": False,
                  "msg": "bindpassword for binddn must be configured."}
        return result

    if len(ldapserver) > 4:
        result = {"ret": False, "msg": "Users can only specify up to 4 LDAP servers."}
        return result
    
    result = {"ret": True}
    return result


def parse_ldapserver(ldapserver):
    serverlist = list()
    portlist = list()
    for server in ldapserver:
        if ':' in server:
            addr = server.split(':')[0]
            port = server.split(':')[-1]
        else:
            addr = server
            port = '389'
        serverlist.append(addr)
        portlist.append(port)
    
    return (serverlist, portlist)


def add_helpmessage(argget):
    argget.add_argument('--ldapserver', type=str, required=True, nargs="+",
                         help='Manually configure LDAP servers by entering each server IP/hostname with port(up to 4 servers allowed). '
                              'The format should be IP:port. If port is not specified, default port 389 will be used. '
                              'e.g. --ldapserver 10.10.10.1:389 10.10.10.2')

    argget.add_argument('--binddn', type=str, help='Specify DN for binding LDAP server with a DN and password. If DN is not specified, try to bind anonymous')
    argget.add_argument('--bindpassword', type=str, help='Specify password for binding LDAP server with a DN and password.')

    argget.add_argument('--rootdn', type=str,
                        help='BMC uses the "ROOT DN" field in Distinguished Name format as root entry of directory tree.'
                             'This DN will be used as the base object for all searches.')
    argget.add_argument('--search_username_attribute', type=str, default='uid',
                        help='This search request must specify the attribute name used to represent user IDs on that server.'
                             'On Active Directory servers, this attribute name is usually sAMAccountName.'
                             'On Novell eDirectory and OpenLDAP servers, it is usually uid. '
                             'Default is uid. Allowable values for ThinkSystem SR635/SR655 should be cn or uid.')
    argget.add_argument('--search_group_filter', type=str,
                        help='This field is used for group authentication, limited to 511 characters, and consists of one or more group names. This parameter is not for ThinkSystem SR635/SR655.')
    argget.add_argument('--search_group_attribute', type=str, default="memberof",
                        help='This field is used by the search algorithm to find group membership infomation for a specific user. Default is memberof. This parameter is not for ThinkSystem SR635/SR655.')


def add_parameter():
    """Add set ldap server parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["ldapserver"] = args.ldapserver
    parameter_info["client_distinguished_name"] = args.binddn
    parameter_info["client_password"] = args.bindpassword
    parameter_info["rootdn"] = args.rootdn
    parameter_info["uid_search_attribute"] = args.search_username_attribute
    parameter_info["group_filter"] = args.search_group_filter
    parameter_info["group_search_attribute"] = args.search_group_attribute
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info["ip"]
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    ldapserver = parameter_info["ldapserver"]
    client_distinguished_name = parameter_info["client_distinguished_name"]
    client_password = parameter_info["client_password"]
    rootdn = parameter_info["rootdn"]
    uid_search_attribute = parameter_info["uid_search_attribute"]
    group_filter = parameter_info["group_filter"]
    group_search_attribute = parameter_info["group_search_attribute"]

    # Set ldap server and check result
    result = lenovo_set_bmc_external_ldap(ip, login_account, login_password, ldapserver, client_distinguished_name, client_password,
                           rootdn, uid_search_attribute, group_filter, group_search_attribute)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

