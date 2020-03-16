###
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


import sys, os
import argparse
import configparser
import redfish

# set _MAXHEADERS to avoid header over 100 error
if sys.version_info.major == 2:
    import httplib
    httplib._MAXHEADERS = 1000
else:
    import http.client
    http.client._MAXHEADERS = 1000


def get_system_url(base_url, system_id, redfish_obj):
    """Get ComputerSystem instance URL    
    :params base_url: URL of the Redfish Service Root
    :type base_url: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params redfish_obj: Response from HTTP
    :type redfish_obj: redfish client object
    :returns: returns string URL to ComputerSystem resource
    """
    # Get ServiceRoot resource
    response_base_url = redfish_obj.get(base_url, None)
    # Get ComputerSystemCollection resource
    systems_url = response_base_url.dict["Systems"]["@odata.id"]
    response_systems_url = redfish_obj.get(systems_url, None)
    count = response_systems_url.dict["Members@odata.count"]
    Members = response_systems_url.dict["Members"]
    # NOTE: Get the ComputerSystem instance list
    system = []
    if not Members:
        return system
    if system_id == "None":
        # Default returns the first instance
        system_url = response_systems_url.dict["Members"][0]["@odata.id"]
        system.append(system_url)
        return system
    elif system_id == "all":
        # Return all system list
        for i in range(response_systems_url.dict['Members@odata.count']):
            system_url = response_systems_url.dict["Members"][i]["@odata.id"]
            system.append(system_url)
            return system
    else:
        # Return parameters specify the system
        for system_x_url in Members:
            system_url = system_x_url["@odata.id"]
            if system_id in system_url:
                system.append(system_url)
                return system
            else:
                return system


def get_extended_error(response_body):
    """Get extended error    
    :params response_body: Response from HTTP
    :type response_body: class 'redfish.rest.v1.RestResponse'
    """
    try:
        expected_dict = response_body.dict
        message_dict = expected_dict["error"]["@Message.ExtendedInfo"][0]
        if "Message" in message_dict:
            message = str(message_dict["Message"])
        else:
            message = str(message_dict["MessageId"])
        return message
    except:
        message = response_body
        return message


def read_config(config_file):
    """Read configuration file infomation    
    :config_file: Configuration file
    :type config_file: string 
    """
    cfg = configparser.ConfigParser()
    try:
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        if os.sep not in config_file:
            config_file = cur_dir + os.sep + config_file

        config_ini_info = {"ip": "", "user": "", "passwd": "", "auth": ""}
        # Check whether the config file exists
        if os.path.exists(config_file):
            cfg.read(config_file)
            # Get the ConnectCfg info
            config_ini_info["ip"] = cfg.get('ConnectCfg', 'BmcIP')
            config_ini_info["user"] = cfg.get('ConnectCfg', 'BmcUsername')
            config_ini_info["passwd"] = cfg.get('ConnectCfg', 'BmcUserpassword')
            config_ini_info['sysid'] = cfg.get('ConnectCfg', 'SystemId')
            try:
                config_ini_info['auth'] = cfg.get('ConnectCfg', 'Auth')
            except:
                config_ini_info['auth'] = 'session'
    except:
        sys.stderr.write("Please check the file path is correct")
        sys.exit(1)
    return config_ini_info


def create_common_parameter_list(description_string="This tool can be used to perform system management via Redfish.", prog_string=None, example_string=None):
    """Add common parameter"""
    # Set prog and description
    if not description_string.endswith('.'):
        description_string = description_string + '.'
    description_fullstring = description_string + " BMC connect information (ip/username/password) is needed. Set them by command line -i,-u,-p or using configuration file (default config.ini)."
    if prog_string and example_string:
        argget = argparse.ArgumentParser(prog=prog_string, epilog=example_string, description=description_fullstring)
    elif prog_string:
        argget = argparse.ArgumentParser(prog=prog_string, description=description_fullstring)
    elif example_string:
        argget = argparse.ArgumentParser(epilog=example_string, description=description_fullstring)
    else:
        argget = argparse.ArgumentParser(description=description_fullstring)
    
    # Add connect parameter
    argget.add_argument('-c', '--config', type=str, default='config.ini', help=('Configuration file(may be overrided by parameters from command line)'))
    argget.add_argument('-i', '--ip', type=str, help=('BMC IP address'))
    argget.add_argument('-u', '--user', type=str, help='BMC user name')
    argget.add_argument('-p', '--passwd', type=str, help='BMC user password')
    argget.add_argument('-s', '--sysid', type=str, default=None, help='ComputerSystem instance id(None: first instance, All: all instances)')
    argget.add_argument('-a', '--auth', type=str, default=None, choices=['session', 'basic'], help='Authentication mode(session or basic), the default is session')
    
    return argget


def parse_parameter(args):
    """parse parameter  
    :args: argparse namespace
    :type args: class 
    """
    config_ini_info = {}
    # Get configuration file info
    config_file = args.config
    config_ini_info = read_config(config_file)

    # Get command line parameter info
    parameter_info = {}
    if args.ip is not None:
        parameter_info["ip"] = args.ip
    if args.user is not None:
        parameter_info["user"] = args.user
    if args.passwd is not None:
        parameter_info["passwd"] = args.passwd
    if args.sysid is not None:
        parameter_info["sysid"] = args.sysid
    if args.auth is not None:
        parameter_info["auth"] = args.auth

    # Use parameters from command line to overrided Configuration file
    for key in parameter_info:
        if parameter_info[key]:
            config_ini_info[key] = parameter_info[key]
    if "sysid" not in config_ini_info:
        config_ini_info["sysid"] = "None"

    # Check auth
    if config_ini_info["auth"] not in ['session', 'basic']:
        config_ini_info["auth"] = 'session'

    # Check connect information
    if not config_ini_info['ip'] or not config_ini_info['user'] or not config_ini_info['passwd']:
        sys.stderr.write("BMC connect information (ip/username/password) is needed. Please provide them by command line -i,-u,-p or configuration file (default config.ini).")
        sys.exit(1)
        
    return config_ini_info
