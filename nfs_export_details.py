#!/usr/bin/env python 

# nfs_export_details.py version 1.0 2017-12-04
# arndt@netapp.com
#
# This script iterates through all volumes and qtrees on a given cluster
# and reports on NFS export policy rules that are in place for each.
#
# Usage: ./nfs_export_details.py <cluster>
#
# THIS SOFTWARE IS PROVIDED BY NETAPP "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN 
# NO EVENT SHALL NETAPP BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Requirements:
# 1. Python 2.6 or higher.
# 2. The NMSDK python modules should be placed in a directory named "NMSDKpy".
#
# Version 1.0 - Initial release.

import sys
import getpass
import time
sys.path.append("NMSDKpy")
from NaServer import *

# Some constants.
VERBOSE=0
DEBUG=0
XML=0
DEV=1

# This is for working in dev environment with an ONTAP simulator.
if DEV:
    import ssl
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        # Legacy Python that doesn't verify HTTPS certificates by default
        pass
    else:
        # Handle target environment that doesn't support HTTPS verification
        ssl._create_default_https_context = _create_unverified_https_context

# Function that will connect to ONTAP API.
def NaConnect(cluster,password):

    s = NaServer(cluster, 1, 30)
    s.set_server_type('FILER')

    # set communication style - typically just 'LOGIN'
    resp = s.set_style('LOGIN')
    if (resp and resp.results_errno() != 0) :
        r = resp.results_reason()
        logmsg("Failed to set authentication style " + r + "\n")
        sys.exit (2)

    # set API transport type - HTTP is the default
    resp = s.set_transport_type('HTTPS')
    if (resp and resp.results_errno() != 0) :
         r = resp.results_reason()
         logmsg("Unable to set transport " + r + "\n")
         sys.exit(2)

    # set communication port
    s.set_port(443)

    # Connect and verify
    s.set_admin_user('admin', password)
    api = NaElement("system-get-version")
    output = s.invoke_elem(api)
    if XML: logmsg(output.sprintf())
    if (output.results_status() == "failed"):
        r = output.results_reason()
        logmsg("Error connecting: " + str(r))
        sys.exit(2) 
    else:
        ontap_version = output.child_get_string("version")
        if VERBOSE: logmsg("Cluster " + cluster + " is running " + ontap_version)

    # return storage object
    return s


# Get a list of volumes.
def get_vols(na):
    mrecs = "1000"
    tag   = ""
    # Use tags with this iter call in case we have a very large list of vols.
    while tag != None:
        # Define the API call.
        api = NaElement("volume-get-iter")
        api.child_add_string("max-records", mrecs)
        desired_attributes = NaElement("desired-attributes")
        api.child_add(desired_attributes)
        volume_attributes = NaElement("volume-attributes")
        desired_attributes.child_add(volume_attributes)
        volume_id_attributes = NaElement("volume-id-attributes")
        volume_attributes.child_add(volume_id_attributes)
        volume_id_attributes.child_add_string("name", "")
        volume_id_attributes.child_add_string("junction-path", "")
        volume_id_attributes.child_add_string("owning-vserver-name", "")
        volume_export_attributes = NaElement("volume-export-attributes")
        volume_attributes.child_add(volume_export_attributes)
        if tag:
            api.child_add_string("tag", tag)
        if XML: logmsg(api.sprintf())
        output = na.invoke_elem(api)
        if XML: logmsg(output.sprintf())
        if (output.results_status() == "failed"):
            r = output.results_reason()
            logmsg("Failed volume-get-iter API call : " + str(r))
        vollist = output.child_get("attributes-list")
        for vol in vollist.children_get():
            id_attrs      = vol.child_get("volume-id-attributes")
            name          = id_attrs.child_get_string("name")
            junction      = id_attrs.child_get_string("junction-path")
            vserver       = id_attrs.child_get_string("owning-vserver-name")
            export_attrs  = vol.child_get("volume-export-attributes")
            # Only examine volumes that are junctioned and have some policy assigned.
            if not junction:
                continue
            if not export_attrs:
                continue
            policy            = export_attrs.child_get_string("policy")
            volumeid          = vserver + ":" + name
            volumes[volumeid] = {}
            volumes[volumeid]['junction'] = junction
            volumes[volumeid]['policy']   = policy
            if DEBUG: logmsg("V:" + volumeid + " J:" + junction + " P:" + policy)
        # Get the tag for the next set of records.
        tag = output.child_get_string("next-tag")

    return 1


# Get a list of qtrees.
def get_qtrees(na):
    mrecs = "500"
    tag   = ""
    # Use tags with this iter call in case we have a very large list of vols.
    while tag != None:
        # Define the API call.
        api = NaElement("qtree-list-iter")
        api.child_add_string("max-records", mrecs)
        desired_attributes = NaElement("desired-attributes")
        api.child_add(desired_attributes)
        qtree_info = NaElement("qtree-info")
        desired_attributes.child_add(qtree_info)
        qtree_info.child_add_string("vserver","")
        qtree_info.child_add_string("volume","")
        qtree_info.child_add_string("qtree","")
        qtree_info.child_add_string("export-policy","")
        if tag:
            api.child_add_string("tag", tag)
        if XML: logmsg(api.sprintf())
        output = na.invoke_elem(api)
        if XML: logmsg(output.sprintf())
        if (output.results_status() == "failed"):
            r = output.results_reason()
            logmsg("Failed qtree-list-iter API call : " + str(r))
        qtreelist = output.child_get("attributes-list")
        for qtree in qtreelist.children_get():
            vserver  = qtree.child_get_string("vserver")
            volume   = qtree.child_get_string("volume")
            name     = qtree.child_get_string("qtree")
            policy   = qtree.child_get_string("export-policy")
            # Skip if no qtree name, this is the volume itself.
            if not name:
                continue
            # Skip if no policy assigned.
            if not policy:
                continue
            volumeid = vserver + ":" + volume
            if volumeid not in qtrees:
                qtrees[volumeid] = {}
            qtrees[volumeid][name] = policy
            if DEBUG: logmsg("V:" + volumeid + " Q:" + name + " P:" + policy)
        # Get the tag for the next set of records.
        tag = output.child_get_string("next-tag")

    return 1


# Get a list of NFS export policies.
def get_policies(na):
    mrecs = "100"
    tag   = ""
    # Use tags with this iter call in case we have a very large list of rules.
    while tag != None:
        # Define the API call.
        api = NaElement("export-rule-get-iter")
        api.child_add_string("max-records", mrecs)
        # Add the next-tag in our call if this is not the first call.
        if tag:
            api.child_add_string("tag", tag)
        if XML: logmsg(api.sprintf())
        output = na.invoke_elem(api)
        if XML: logmsg(output.sprintf())
        if (output.results_status() == "failed"):
            r = output.results_reason()
            logmsg("Failed export-rule-get-iter API call : " + str(r))
        # Parse the output.
        exports = output.child_get("attributes-list")
        for export in exports.children_get():
            vserver  = export.child_get_string("vserver-name")
            policy   = export.child_get_string("policy-name")
            index    = export.child_get_string("rule-index")
            if vserver not in policies:
                policies[vserver] = {}
            if policy not in policies[vserver]:
                policies[vserver][policy] = {}
            policies[vserver][policy][index] = {}
            client    = export.child_get_string("client-match")
            anon      = export.child_get_string("anonymous-user-id")
            suid      = export.child_get_string("is-allow-set-uid-enabled")
            ro_rule   = export.child_get("ro-rule")
            ro_sec    = ro_rule.child_get_string("security-flavor")
            rw_rule   = export.child_get("rw-rule")
            rw_sec    = rw_rule.child_get_string("security-flavor")
            superuser = export.child_get("super-user-security")
            sup_sec   = superuser.child_get_string("security-flavor")
            policies[vserver][policy][index]['clients'] = client
            policies[vserver][policy][index]['anon']    = anon
            policies[vserver][policy][index]['suid']    = suid
            policies[vserver][policy][index]['ro']      = ro_sec
            policies[vserver][policy][index]['rw']      = rw_sec
            policies[vserver][policy][index]['root']    = sup_sec
            if DEBUG: logmsg("P:" + policy)
            if DEBUG: print(policies[vserver][policy][index])
        # Get the tag for the next set of records.
        tag = output.child_get_string("next-tag")

    return 1


# Subroutine to format a set of policy rules for printing.
def format_policy_rules(rules):
    string = ""
    for index in sorted(rules):
        if string:
            string = string + "\n,,,,,"
        string = string + "ruleindex:" + index
        for key in rules[index]:
            string = string +  "  " + key + ":" + rules[index][key]

    return string


# Simple function to log a message with a timestamp.
def logmsg(msg):
    datetime = time.strftime("%c")
    msg = datetime + ": " + msg
    print(msg)
    return 1
    

# Main program.

# Parse CLI.
if len(sys.argv) < 2:
    print >> sys.stderr, ("Usage: nfs_export_details.py <cluster_name>")
    sys.exit(2)
cluster = sys.argv[1]

# Get cluster passwords.
temp = sys.stdout
sys.stdout = sys.stderr
password = getpass.getpass("Enter admin password: ")
sys.stdout = temp

# Connect to the cluster.
na = NaConnect(cluster,password)

# Get volume details
volumes = {}
get_vols(na)

# Get qtree details
qtrees = {}
get_qtrees(na)

# Get NFS export policy details
na.set_vserver('')
policies = {}
get_policies(na)

# Print output in CSV format.
# Loop through list of volumes, printing details as we go.
print("Path,Type,Vserver,Name,Export Policy Name,Export Policy Rules")
for volumeid in volumes:
    volumestr = volumeid.split(":")
    vserver   = volumestr[0]
    volume    = volumestr[1]
    path      = volumes[volumeid]['junction']
    policy    = volumes[volumeid]['policy']
    if policy in policies[vserver]:
        rules = format_policy_rules(policies[vserver][policy])
    else:
        rules = "No policy rules exists"
    print(path + ",Volume," + vserver + "," + volume + "," + policy + "," + rules)
    # Now print details for all the qtrees in this volume.
    if volumeid in qtrees:
        for qtree in qtrees[volumeid]:
            qtpath = path + "/" + qtree
            policy = qtrees[volumeid][qtree]
            if policy in policies[vserver]:
                rules = format_policy_rules(policies[vserver][policy])
            else:
                rules = "No policy rules exists"
            print(qtpath + ",Qtree," + vserver + "," + volume + "/" + qtree + "," + policy + "," + rules)
