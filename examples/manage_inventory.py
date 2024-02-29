###
#
# Lenovo Redfish examples - Manage inventory
#
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
import redfish
import json
import lenovo_utils as utils


def create_parameter(supported_subcmd_list):
    """Create parameter for inventory management"""
    
    parser = utils.create_common_parameter_list("This tool can be used to perform inventory management via Redfish.")
    subparsers = parser.add_subparsers(help='sub-command help')
    
    add_inventory_subcmds2subparsers(subparsers, supported_subcmd_list)
    
    ret_args = parser.parse_args()
    return ret_args


def add_inventory_subcmds2subparsers(subparsers, subcmdlist):
    if 'getinventories' in subcmdlist:
        # create the sub parser for the 'getinventories' sub command
        parser_getinventories = subparsers.add_parser('getinventories', help='use getinventories to get all inventory information')
        parser_getinventories.set_defaults(func=subcmd_getinventories_main)
        
    if 'getsystem' in subcmdlist:
        # create the sub parser for the 'getsystem' sub command
        parser_getsystem = subparsers.add_parser('getsystem', help='use getsystem to get system inventory information')
        parser_getsystem.set_defaults(func=subcmd_getsystem_main)
        
    if 'getcpu' in subcmdlist:
        # create the sub parser for the 'getcpu' sub command
        parser_getcpu = subparsers.add_parser('getcpu', help='use getcpu to get processor inventory information')
        parser_getcpu.set_defaults(func=subcmd_getcpu_main)
        
    if 'getmemory' in subcmdlist:
        # create the sub parser for the 'getmemory' sub command
        parser_getmemory = subparsers.add_parser('getmemory', help='use getmemory to get memory inventory information')
        parser_getmemory.set_defaults(func=subcmd_getmemory_main)
        
    if 'getstorage' in subcmdlist:
        # create the sub parser for the 'getstorage' sub command
        parser_getstorage = subparsers.add_parser('getstorage', help='use getstorage to get storage inventory information')
        parser_getstorage.set_defaults(func=subcmd_getstorage_main)
        
    if 'getnic' in subcmdlist:
        # create the sub parser for the 'getnic' sub command
        parser_getnic = subparsers.add_parser('getnic', help='use getnic to get nic inventory information')
        parser_getnic.set_defaults(func=subcmd_getnic_main)
        
    if 'getpsu' in subcmdlist:
        # create the sub parser for the 'getpsu' sub command
        parser_getpsu = subparsers.add_parser('getpsu', help='use getpsu to get powersupply inventory information')
        parser_getpsu.set_defaults(func=subcmd_getpsu_main)
        
    if 'getbmc' in subcmdlist:
        # create the sub parser for the 'getbmc' sub command
        parser_getbmc = subparsers.add_parser('getbmc', help='use getbmc to get BMC inventory information')
        parser_getbmc.set_defaults(func=subcmd_getbmc_main)


def subcmd_getinventories_main(args, parameter_info, subcmdlist):
    """call sub script to perform the getinventories sub command"""
    sys.stdout.write("{")
    sys.stdout.write("\n\"SystemInventory\":\n")
    subcmd_getsystem_main(args, parameter_info)
    if 'getcpu' in subcmdlist:
        sys.stdout.write(",\n\n\"CpuInventory\":\n")
        subcmd_getcpu_main(args, parameter_info)
    if 'getmemory' in subcmdlist:
        sys.stdout.write(",\n\n\"MemoryInventory\":\n")
        subcmd_getmemory_main(args, parameter_info)
    if 'getstorage' in subcmdlist:
        sys.stdout.write(",\n\n\"StorageInventory\":\n")
        subcmd_getstorage_main(args, parameter_info)
    if 'getnic' in subcmdlist:
        sys.stdout.write(",\n\n\"NicInventory\":\n")
        subcmd_getnic_main(args, parameter_info)
    if 'getpsu' in subcmdlist:
        sys.stdout.write(",\n\n\"PsuInventory\":\n")
        subcmd_getpsu_main(args, parameter_info)
    if 'getbmc' in subcmdlist:
        sys.stdout.write(",\n\n\"BmcInventory\":\n")
        subcmd_getbmc_main(args, parameter_info)
    sys.stdout.write("\n}")


def subcmd_getsystem_main(args, parameter_info):
    """call sub script to perform the getsystem sub command"""
    
    from get_system_inventory import get_system_inventory
    result = get_system_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getcpu_main(args, parameter_info):
    """call sub script to perform the getcpu sub command"""
    
    from get_cpu_inventory import get_cpu_inventory
    result = get_cpu_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getmemory_main(args, parameter_info):
    """call sub script to perform the getmemory sub command"""
    
    from get_memory_inventory import get_memory_inventory
    result = get_memory_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'], None)
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getstorage_main(args, parameter_info):
    """call sub script to perform the getstorage sub command"""
    
    from get_storage_inventory import get_storage_inventory
    result = get_storage_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getnic_main(args, parameter_info):
    """call sub script to perform the getnic sub command"""
    
    from get_nic_inventory import get_nic_inventory
    result = get_nic_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getpsu_main(args, parameter_info):
    """call sub script to perform the getpsu sub command"""
    
    from get_psu_inventory import get_psu_inventory
    result = get_psu_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entry_details'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])


def subcmd_getbmc_main(args, parameter_info):
    """call sub script to perform the getbmc sub command"""
    
    from get_bmc_inventory import get_bmc_inventory
    result = get_bmc_inventory(parameter_info['ip'], parameter_info['user'], parameter_info['passwd'], parameter_info['sysid'])
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    subcmd_list = ['getinventories', 'getsystem', 'getcpu', 'getmemory', 'getstorage', 'getnic', 'getpsu', 'getbmc']
    parsed_args = create_parameter(subcmd_list)
    parsed_parameter_info = utils.parse_parameter(parsed_args)
    
    # Call related function to perform sub command
    if 'func' in parsed_args and parsed_args.func:
        if parsed_args.func is subcmd_getinventories_main:
            parsed_args.func(parsed_args, parsed_parameter_info, subcmd_list)
        else:
            parsed_args.func(parsed_args, parsed_parameter_info)
    else:
        sys.stderr.write('error: too few arguments. use -h to get help information')
        sys.exit(1)
