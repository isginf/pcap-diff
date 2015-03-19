#!/usr/bin/python
#
# Diff two or more pcap files and write a pcap file with different packets as result
#
#
# You need to install scapy to use this script
# -> pip install scapy
#
# Copyright 2013 ETH Zurich, ISGINF, Bastian Ballmann
# E-Mail: bastian.ballmann@inf.ethz.ch
# Web: http://www.isg.inf.ethz.ch
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# It is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License.
# If not, see <http://www.gnu.org/licenses/>.


###[ Loading modules ]###

import sys
import getopt
from scapy.all import rdpcap, wrpcap, Packet, NoPayload


###[ Parsing parameter ]###

output_file = None
input_files = []
complete_diff = False
ignore_source = False
ignore_source_ip = False
ignore_dest_ip = True
ignore_source_mac = True
ignore_macs = False
ignore_seq_ack = False
ignore_ip_id = False
ignore_header = None
diff_only_left = False
diff_only_right = False
be_quite = False

def usage():
    print sys.argv[0]
    print """
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Diff two or more pcap files
    Programmed by Bastian Ballmann <bastian.ballmann@inf.ethz.ch>
    Version 1.0.0
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

    -i <input_file> (use multiple times)
    -o <output_file>
    -c (complete diff, dont ignore ttl, checksums and timestamps) - False by default
    -l diff only left side (first pcap file)
    -r diff only right side (not first pcap file)
    -f s (ignore src ip / mac) - False by default
    -f sm (ignore src mac) - True by default
    -f si (ignore src ip) - False by default
    -f di (ignore dst ip) - False by default
    -f m (ignore mac addresses) - False by default
    -f sa (ignore tcp seq and ack num) - False by default
    -f ii (ignore ip id) - False by default
    -f <scapy header name>
    -q be quite

    Example usage with ignore mac addresses
    pcap_diff.py -i client.dump -i server.dump -o diff.pcap -f m

    """
    sys.exit(1)

try:
    cmd_opts = "cf:i:lo:qr"
    opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-i":
        input_files.append(opt[1])
    elif opt[0] == "-o":
        output_file = opt[1]
    elif opt[0] == "-c":
        complete_diff = True
    elif opt[0] == "-l":
        diff_only_left = True
    elif opt[0] == "-r":
        diff_only_right = True
    elif opt[0] == "-q":
        be_quite = True
    elif opt[0] == "-f":
        if opt[1] == "s":
            ignore_source = True
        elif opt[1] == "sm":
            ignore_source_mac = True
        elif opt[1] == "sa":
            ignore_seq_ack = True
        elif opt[1] == "ii":
            ignore_ip_id = True
        elif opt[1] == "si":
            ignore_source_ip = True
        elif opt[1] == "di":
            ignore_dest_ip = True
        elif opt[1] == "m":
            ignore_macs = True
        else:
            ignore_header = opt[1]
    else:
        usage()

if len(input_files) < 2:
   print "Need at least 2 input files to diff"
   sys.exit(1)


###[ Subroutines ]###

def flatten(d, parent_key=''):
    """
    Flatten a packet to a dict
    Remove checksums (can be different due to calculation in netdev firmware)
    """
    items = []

    # skip scapy internal fields
    skip_fields = ['fieldtype', 'underlayer', 'initialized', 'fieldtype',
                   'default_fields', 'aliastypes', 'post_transforms',
                   'packetfields', 'overloaded_fields', 'sent_time']
    
    for k, v in d.items():
        fullk = "%s_%s" % (parent_key, k)
        # No complete diff? Ignore checksum, ttl and time
        if not complete_diff and (k == "chksum" or k == "ttl" or k == "time"): 
            continue

        # skip time value of deeper layers (they all get it from Packet)
        if parent_key and k == "time":
            continue
        
        # Ignore source IP?
        if (ignore_source or ignore_source_ip) and k == "src":
            continue

        # Ignore dest IP?
        if ignore_dest_ip and k == "dst":
            continue

        # Ignore TCP seq and ack num?
        if ignore_seq_ack and (k == "seq" or k == "ack"):
            continue

        # Ignore IP ID?
        if ignore_ip_id and k == "id":
            continue

        # Ignore custom header field?
        if ignore_header and fullk == ignore_header:
            continue

        new_key = parent_key + '_' + k if parent_key else k

        # payload is Packet or str
        # stop at NoPayload payload
        if k == "payload" and isinstance(v, NoPayload):
            continue
        elif k == "payload" and isinstance(v, Packet):
            new_key = v.__class__.__name__ + "_" + k
            items.extend(flatten(v.__dict__, new_key).items())
        elif k == "payload":
            new_key = v.__class__.__name__ + "_" + k
            items.append((new_key, v.payload))
        elif k == "fields" and isinstance(v, Packet):
            new_key = v.__class__.__name__ + "_" + k
            items.extend(flatten(v, new_key).items())
        elif k in skip_fields:
            continue  # skip internal, unneeded fields
        elif isinstance(v, dict):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))

    return dict(items)


def serialize(packet):
    """
    Serialize flattened packet
    """
    pdict = packet.__dict__
    
    # remove mac addresses?
    if ignore_macs and pdict.get("fields"):
       if pdict["fields"].get("src"): del pdict["fields"]["src"] 
       if pdict["fields"].get("dst"): del pdict["fields"]["dst"]

    if (ignore_source or ignore_source_mac) and pdict.get("fields"):
        if pdict["fields"].get("src"): del pdict["fields"]["src"] 

    flat_packet = flatten(pdict)
    serial = ""

    for key in sorted(flat_packet):
        serial += str(key) + ": " + str(flat_packet[key]) + " | "

    return serial


def read_dump(pcap_file):
    """
    Read PCAP file
    Return dict of packets with serialized flat packet as key
    """
    dump = {}
    count = 0

    if not be_quite:
        sys.stdout.write("Reading file " + pcap_file + "\n")
        sys.stdout.flush()

    for packet in rdpcap(pcap_file):
        if not be_quite:
            sys.stdout.write(":")
            sys.stdout.flush()

        count += 1
        dump[serialize(packet)] = packet

    if not be_quite:
        sys.stdout.write("\nFound " + str(count) + " packets\n\n")

    return dump


###[ MAIN PART ]###

# Parse pcap files
dumps = []

for input_file in input_files:
    dumps.append(read_dump(input_file))

# Diff the dumps
diff_counter = 0
diff_packets = []
base_dump = dumps.pop(0)

if not be_quite:
    print "Diffing packets"

for packet in base_dump.values():
    serial_packet = serialize(packet)
    found_packet = False

    if not be_quite:
        sys.stdout.write(":")
        sys.stdout.flush()
    
    for dump in dumps:
        if dump.get(serial_packet):
            del dump[serial_packet]
            found_packet = True

    if not diff_only_right and not found_packet:
        if not be_quite:
            print " <<< " + packet.summary()
        diff_packets.append(packet)

if not diff_only_left:
    for dump in dumps:
        if len(dump.values()) > 0:
            diff_packets.extend(dump.values())

            if not be_quite:
                for packet in dump.values():
                    print " >>> " + packet.summary()

if not be_quite:
    print "\nFound " + str(len(diff_packets)) + " different packets\n"

# Write pcap diff file?
if output_file:
    if not be_quite:
        print "Writing " + output_file
    wrpcap(output_file, diff_packets)
