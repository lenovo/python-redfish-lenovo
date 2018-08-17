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


import sys
import redfish
import argparse
import configparser


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
    expected_dict = response_body.dict
    message_dict = expected_dict["error"]["@Message.ExtendedInfo"][0]
    return str(message_dict["Message"])


def read_config(config_file):
    """Read configuration file infomation    
    :config_file: Configuration file
    :type config_file: string 
    """
    cfg = configparser.ConfigParser()
    try:
        cfg.read(config_file)
        config_ini_info = {}
        # Get the ConnectCfg info
        config_ini_info["ip"] = cfg.get('ConnectCfg', 'BmcIP')
        config_ini_info["user"] = cfg.get('ConnectCfg', 'BmcUsername')
        config_ini_info["passwd"] = cfg.get('ConnectCfg', 'BmcUserpassword')
        config_ini_info['sysid'] = cfg.get('ConnectCfg', 'SystemId')
    except:
        sys.stderr.write("Please check the file path is correct")
        sys.exit(1)
    return config_ini_info


def create_common_parameter_list():
    """Add common parameter"""
    argget = argparse.ArgumentParser(description="This tool can be used to perform system management via Redfish")
    argget.add_argument('-c', '--config', type=str, default='config.ini', help=('Configuration file(may be overrided by parameters from command line)'))
    argget.add_argument('-i', '--ip', type=str, help=('BMC IP address'))
    argget.add_argument('-u', '--user', type=str, help='BMC user name')
    argget.add_argument('-p', '--passwd', type=str, help='BMC user password')
    argget.add_argument('-s', '--sysid', type=str, default=None, help='ComputerSystem instance id(None: first instance, All: all instances)')
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
        parameter_info['sysid'] = args.sysid
    # Get the set chassis indicator led parameter info
    try:
        if args.ledstatus is not None:
            parameter_info['ledstatus'] = args.ledstatus
    except:
        pass
    # Get the reset system parameter info
    try:    
        if args.resettype is not None:
            parameter_info['reset_keys_type'] = args.resettype
    except:
         pass    
    # Get the disable , enable userid info
    try:    
        if args.userid is not None:
            parameter_info['userid'] = args.userid
    except:
        pass
    # Get the set reset system parameter info
    try:    
        if args.resettype is not None:
            parameter_info['reset_type'] = args.resettype
    except:
         pass
    # Get the set server assettag parameter info
    try:    
        if args.assettag is not None:
            parameter_info['asset_tag'] = args.assettag
    except:
         pass
    # Get the set server boot once parameter info 
    try:    
        if args.bootsource is not None:
            parameter_info['boot_source'] = args.bootsource
    except:
         pass
    # Get the set bios attribute parameter info
    try:    
        if args.name is not None and args.value is not None:
            parameter_info['attribute_name'] = args.name
            parameter_info['attribute_value'] = args.value
    except:
         pass
    # Get the set bios password parameter info
    try:    
        if args.name is not None and args.biospasswd is not None:
            parameter_info['bios_password_name'] = args.name
            parameter_info['bios_password'] = args.biospasswd
    except:
         pass
    # Get the set vlanid parameter info
    try:    
        if args.vlanid is not None and args.vlanenable is not None:
            parameter_info['vlanid'] = args.vlanid
            parameter_info['vlanEnable'] = args.vlanenable
    except:
         pass
    # Get the set manager ntp parameter info
    try:    
        if args.ntpserver is not None and args.protocol is not None:
            parameter_info['ntp_server'] = args.ntpserver
            parameter_info['ProtocolEnabled'] = args.protocol
    except:
         pass
    # Get the bios attribute parameter info  
    try:    
        if args.name is not None:
            parameter_info['attribute_name'] = args.name
    except:
         pass
    # Get the update user role parameter info
    try:    
        if args.userid is not None and args.roleid is not None:
            parameter_info['userid'] = args.userid
            parameter_info['roleid'] = args.roleid
    except:
         pass
    # Get the update user password pasrmeter info
    try:    
        if args.userid is not None and args.newpasswd is not None:
            parameter_info['userid'] = args.userid
            parameter_info['new_passwd'] = args.newpasswd
    except:
         pass
    # Get schema pasrmeter info
    try:    
        if args.schema is not None:
            parameter_info['schemaprefix'] = args.schema
    except:
         pass
    # Get bios attribute pasrmeter info
    try:    
        if args.bios is not None:
            parameter_info['bios_get'] = args.bios
        else:
            parameter_info['bios_get'] = args.bios
    except:
         pass
    # Update firmware
    try:    
        if args.imageurl is not None and args.targets is not None and args.protocol is not None:
            parameter_info['imageurl'] = args.imageurl
            parameter_info['targets'] = args.targets
            parameter_info['protocol'] = args.protocol
    except:
         pass
    # Set serial interfaces attribute
    try:
        if args.bitrate is not None or args.stopbits is not None or args.parity is not None or args.interface is not None:
            parameter_info['bitrate'] = args.bitrate
            parameter_info['stopbits'] = args.stopbits
            parameter_info['parity'] = args.parity
            parameter_info['interface'] = args.interface
    except:
        pass
    # Use parameters from command line to overrided Configuration file
    for key in parameter_info:
        if parameter_info[key]:
            config_ini_info[key] = parameter_info[key]
    
    return config_ini_info
