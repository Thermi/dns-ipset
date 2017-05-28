#! /bin/env python3

import socket
import json
import tempfile
import sys
import argparse
import os
import subprocess

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class ipset_updater:    
    temporary_v4 = "dns-ipset_ipv4"
    temporary_v6 = "dns-ipset_ipv6"
    ipsets = list()
    configuration = None
    config_path = "/etc/dns-ipset.js"
    
    def unify(self, first_list):
        second_list = list()
        found = 0
        
        for i in first_list:
            found = 0
            for j in second_list:
                # if we already have that address, continue with the next one.
                if i == j:
                    found = 1
                    break
            if found == 0:
                second_list.append(i)
        return second_list

    def cleanup_duplicate_addresses(self, records):
        known = list()
        for i in records:
            found = False
            for j in known:
                if i.address == j.address and i.protocol == j.protocol and i.port == j.port:
                    found = True
            if not found:
                known.append(i)
        return known

    # load config
    def load_config(self):
        config=None
        try:
            with open(self.config_path, 'r') as configuration_handle:
                config=json.load(configuration_handle)
            self.configuration = config
            return True
        except:
            eprint ("")
            eprint ("ERROR: An exception occured:")
            eprint ("{}".format(sys.exc_info()))
            eprint ("")
            return False

        eprint ("Failed to load the configuration.\n")
        return False
    
    # resolve the name
    def resolve_name(self, name):
        records = list()
        list_v4 = list()
        list_v6 = list()
        try:
            records = socket.getaddrinfo(name, '80')
        except socket.gaierror:
            eprint ("")
            eprint ("Name: {}".format(name))
            eprint ("ERROR: An exception occured:")
            eprint ("{}".format(sys.exc_info()))
            eprint ("")
        else:
            for i in records:
                alreadyAdded = False
                # IPv4
                if i[0] == socket.AddressFamily.AF_INET and i[1] == socket.SocketKind.SOCK_STREAM:
                    # Check if the record is already in the list
                    for j in list_v4:
                        if j == i[4][0]:
                            alreadyAdded = True
                            break
                    if not alreadyAdded:
                        list_v4.append(i[4][0])
                elif i[0] == socket.AddressFamily.AF_INET6 and i[1] == socket.SocketKind.SOCK_STREAM:
                    for j in list_v6:
                        if j == i[4][0]:
                            alreadyAdded = True
                            break
                    if not alreadyAdded:
                        list_v6.append(i[4][0])
        return list_v4, list_v6

    def start_resolving(self):
        sets = self.configuration
        for i in sets: 
            for j in i['FQDNs']:
                try:
                    if self.verbose:
                        print ("Resolving {}".format(j["FQDN"]))
                    v4, v6 = self.resolve_name(j['FQDN'])
                    v4 = self.unify(v4)
                    v6 = self.unify(v6)
                except:
                    eprint ("")
                    eprint ("ERROR: An exception occured:")
                    eprint ("{}".format(sys.exc_info()))
                    eprint ("")
                    j['success'] = False
                if v4 == [] and v6 == []:
                    j['success'] = False
                else:
                    j['success'] = True
                    j['resolved'] = dict()
                    j['resolved']['v4'] = v4
                    j['resolved']['v6'] = v6

# saves the resolved names to a file in json structure
# the content has the following structure
# sets (list)
# sets[i] (dict) (keys: 'name', 'FQDNs' )
# sets[i]['name'] (string) (name of the set)
# sets[i]['FQDNs'] (list)
# sets[i]['FQDNs'][j] (dict) (keys: FQDN, protocol, port)
# sets[i]['FQDNs'][j]['FQDN'] (string)
# sets[i]['FQDNs'][j]['protocol'] (string) (TCP, UDP, or NA (Non Applicable))
# sets[i]['FQDNs'][j]['port'] (integer)
# sets[i]['FQDNs'][j]['success'] (bool) (TRUE if that name was resolved, FALSE, if it wasn't)
# sets[i]['FQDNs'][j]['resolved'] (dict)
# sets[i]['FQDNs'][j]['resolved']['v4'] (list) (lists the value of all A    records of that FQDN)
# sets[i]['FQDNs'][j]['resolved']['v6'] (list) (lists the value of all AAAA records of that FQDN)

# TODO in the secondary call:
#  - derive actual ipset name from the given name and the IP versions (e.g. name := znc -> znc_v4, znc_v6)
#  - put FQDN that were the names of the records into the comment field of the records
#  - specify the protocol and port, if given
#  - handle success or failure
#  - create a new set for IPv4, fill it with the data, then swap it, log the content of the old one to some place
#  - create a new set for IPv6, fill it with the data, then swap it, log the content of the old one to some place

    
    def validate_config(self):
        # we expect the following structure:
        # sets (list) (list of sets that contain DNS names)
        # sets[i] (dict) (keys: 'name', 'FQDNs')
        # sets[i]['name'] (string) name of the set
        # sets[i]['FQDNs'] (list) (a list of dicts)
        # sets[i]['FQDNs'][j] (dict) ((keys: FQDN, protocol , port))
        # sets[i]['FQDNs'][j]['FQDN'] (string) (The FQDN)
        # sets[i]['FQDNs'][j]['protocol'] (string) (TCP, UDP, NA (Non Applicable))
        # sets[i]['FQDNs'][j]['port'] (integer)
        
        configuration = self.configuration
        try:
            if type(configuration['sets']) != list:
                eprint("The structure contained in 'sets' has to be a list, found type {}".format(type(configuration['sets'])))
        except:
            eprint ("")
            eprint ("ERROR: An exception occured:")
            eprint ("{}".format(sys.exc_info()))
            eprint ("")
            return False
        self.configuration = self.configuration['sets']
        configuration=self.configuration
        try:
            for i in configuration:
                if type(i) != dict:
                    eprint ("Elements in the list must be a dict.")
                    return False
                for j in ['name', 'FQDNs']:
                    try:
                        i[j]
                    except:
                        eprint ("")
                        eprint ("ERROR: An exception occured:")
                        eprint ("{}".format(sys.exc_info()))
                        eprint ("")
                        return False
                for j in i['FQDNs']:
                    try:
                        j['protocol']
                        j['port']
                    except:
                        eprint ("")
                        eprint ("ERROR: An exception occured:")
                        eprint ("{}".format(sys.exc_info()))
                        eprint ("")
                        return False
        except:
            eprint ("")
            eprint ("ERROR: An exception occured:")
            eprint ("{}".format(sys.exc_info()))
            eprint ("")
            return False
        return True


    def run(self):
        parser = argparse.ArgumentParser(description="Updates contents of ipsets from DNS.")
        parser.add_argument('-c',
                '--config',
                dest = 'config',
                default =   self.config_path,
                help = 'path to the configuration file',
                nargs = '?'
            )
        parser.add_argument('-v',
                '--verbose',
                action='store_true',
                help="Enables verbose mode",
                dest="verbose"
            )

        args = parser.parse_args()
        self.config_path = args.config
        self.verbose = args.verbose
        # something something
        
        # load the config
       
        if not self.load_config():
            sys.exit(1)
            
        if not self.validate_config():
            eprint("Failed to validate the config.\n")
            sys.exit(2)

        # actually resolve stuff
        if self.verbose:
            print ("Starting to resolve FQDNs.")

        self.start_resolving()
        
        if self.verbose:
            print ("Finished resolving the FQDNs.")

        if self.verbose:
            print ("Starting to update the ipsets.")
        
        self.load_new_sets()

        if self.verbose:
            print ("Finished updating ipsets.")
        
            
            
    # the content has the following structure
    # sets (list)
    # sets[i] (dict) (keys: 'name', 'FQDNs' )
    # sets[i]['name'] (string) (name of the set)
    # sets[i]['FQDNs'] (list)
    # sets[i]['FQDNs'][j] (dict) (keys: FQDN, protocol, port)
    # sets[i]['FQDNs'][j]['FQDN'] (string)
    # sets[i]['FQDNs'][j]['protocol'] (string) (TCP, UDP, or NA (Non Applicable))
    # sets[i]['FQDNs'][j]['port'] (integer)
    # sets[i]['FQDNs'][j]['success'] (bool) (TRUE if that name was resolved, FALSE, if it wasn't)
    # sets[i]['FQDNs'][j]['resolved'] (dict)
    # sets[i]['FQDNs'][j]['resolved']['v4'] (list) (lists the value of all A    records of that FQDN)
    # sets[i]['FQDNs'][j]['resolved']['v6'] (list) (lists the value of all AAAA records of that FQDN)
    
    def generate_file_header(self, name, settype="hash:ip", comment=True, family="inet", hashsize=1024, maxelem=65535):
        format_string=None
        if comment:
            format_string = "create {} {} family {} hashsize {} maxelem {} comment"
        else:
            format_string = "create {} {} family {} hashsize {} maxelem {}"
        return format_string.format(name, settype, family, hashsize, maxelem)
    
    def generate_commands(self, ipset, name, family="v4"):
        if family != "v4" and family != "v6":
            raise ValueError ("""family can only be "v4" or "v6" """)
            return False
        records = list()
        
        for i in ipset["FQDNs"]:
            FQDN = i['FQDN']
            protocol = i['protocol']
            port = i['port']
            if i["success"]:
                for j in i['resolved'][family]:
                    records.append(ipset_record(name, j, protocol, port, FQDN))
        return records

    
    # this method checks for what ipset type is required for the generated records (e.g. if hash:ip or hash:ip,port)
    # @records: list
    def check_records_for_type(self, records):
        # default to "hash:ip"
        necessary_type = "hash:ip"
        for i in records:
            if i.protocol != "NA":
                necessary_type = "hash:ip,port"
        return necessary_type
    
    def restore_file(self, filename):
        cmd = "ipset -f {} restore".format(filename).split(" ")
        
        process = subprocess.Popen(cmd)
        process.wait()
        
        if process.returncode != 0:
            print("Restoring the file {} failed with code {}".format(filename, process.returncode))
            return False
        
    
    def derive_names(self, name):
        v4 = "_v4"
        v6 = "_v6"
        return "{}{}".format(name, v4), "{}{}".format(name, v6)
    
    def destroy_set(self, set_1):
        cmd = "ipset destroy {}".format(set_1).split(" ")
        
        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            print("Deleting the ipset {} failed with code {}".format(set_1, process.returncode))
            return False
        return True
    
    def swap_sets (self, set_1, set_2):
        cmd = "ipset swap {} {}".format(set_1, set_2).split(" ")

        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            eprint("Swapping the ipsets {} and {} failed with code {}".format(set_1, set_2, process.returncode))
            return False
        return True
    
    def write_header(self, temporary_file_handle, header):
        temporary_file_handle.write(bytearray("{}\n".format(header), 'utf-8'))
        temporary_file_handle.flush()
    
    def write_records(self, temporary_file_handle, records):
        for i in records:
            temporary_file_handle.write(bytearray("{}\n".format(i), 'utf-8'))
        temporary_file_handle.flush()
    
    def reset_file_descriptor(self, descriptor):
        descriptor.seek(0)
        descriptor.truncate()
    
    def load_new_sets(self):
        # create a temporary file that we can use to store the new sets.
        temporary_file = tempfile.NamedTemporaryFile()
        number_of_ips = 0
        # iterate over all sets, based on their FQDNs
        for i in self.configuration:
            temporary_file.file.seek(0)
            # derive the names for the sets
            name_v4, name_v6 = self.derive_names(i["name"])
            
            settype = ""
            set_name = ""
            
            setname = self.temporary_v4
            
            # create the new sets, depending on the type.
            ipset_records  = self.generate_commands(i, setname, family="v4")
            
            settype = self.check_records_for_type(ipset_records)
            ipset_records = self.cleanup_duplicate_addresses(ipset_records)

            # skip sets that failed to update
            if len(ipset_records) == 0:
                continue
            number_of_ips += len(ipset_records)
            # check all the records for what type is actually required (just IPs or 
            
            # we do IPv4 first.
            self.write_header(temporary_file.file, self.generate_file_header(setname, settype=settype))
            
            for j in ipset_records:
                try:
                    # write ipset commmands to file as bytes encoded as UTF-8
                    temporary_file.file.write(bytearray("{}\n".format(j), 'utf-8'))
                except:
                    eprint ("")
                    eprint ("ERROR: An exception occured:")
                    eprint ("{}".format(sys.exc_info()))
                    eprint ("")
            
            temporary_file.file.flush()
            
            # load the new records into the new set
            self.restore_file(temporary_file.name)
            
            # swap the set
            self.swap_sets(setname, name_v4)
            
            # destroy the old set
            self.destroy_set(setname)
            self.reset_file_descriptor(temporary_file.file)
            
            # do IPv6
            
            setname = self.temporary_v6       
            
            ipset_records  = self.generate_commands(i, setname, family="v6")
            
            settype = self.check_records_for_type(ipset_records)
            ipset_records = self.cleanup_duplicate_addresses(ipset_records)
            
            self.write_header(temporary_file.file, self.generate_file_header(setname, family="inet6", settype=settype))
            
            for j in ipset_records:
                try:
                    # write ipset commmands to file as bytes encoded as UTF-8
                    temporary_file.file.write(bytearray("{}\n".format(j), 'utf-8'))
                except:
                    eprint ("")
                    eprint ("ERROR: An exception occured:")
                    eprint ("{}".format(sys.exc_info()))
                    eprint ("")
            
            temporary_file.file.flush()
            
            # load the new records into the new set
            self.restore_file(temporary_file.name)

            # swap the set
            self.swap_sets(setname, name_v6)
            
            # destroy the old set
            self.destroy_set(setname)
            self.reset_file_descriptor(temporary_file.file)
                
        
        if self.verbose:
            print ("Loaded {} new IPs into the sets".format(number_of_ips))

        return True
    
class ipset_record():
    ipset_name = None
    address = None
    protocol = None
    port = None
    comment = None
    
    def __init__(self, ipset_name, address, protocol, port, comment = False):
        self.ipset_name = ipset_name
        self.address = address
        self.protocol = protocol
        self.port = port
        self.comment = comment
        
    # custom representation that generates an "add x y" line or generate_add_line() ?
    # also: Take care of special ipv4 or ipv6 name suffixes here?
    def __repr__(self):
        if self.protocol != "NA":
            if self.comment != False:
                return """add {} {},{}:{} comment "{}" """.format(self.ipset_name, self.address, self.protocol, self.port, self.comment)
            else:
                return "add {} {},{}:{}".format(self.ipset_name, self.address, self.protocol, self.port)
        else:
            return "add {} {}".format(self.ipset_name, self.address)
   
if __name__ == '__main__':
    updater = ipset_updater()
    updater.run()