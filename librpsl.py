__author__ = 'stavros'
import sys
from xml.dom.minidom import parseString
import xml.etree.ElementTree as ET

import communicator
import parsers
import xmlGenerator
import libtools as tools

help_message = "Please run again by typing parser -a <ASXXX>"
ripe_db_url = "https://rest.db.ripe.net"
default_db_source = "ripe"
params = dict()


def collectPeeringFilters(allpeers):
    filter_set = set()
    for val in allpeers.itervalues():
        filter_set.update(val.getAllFilters())

    print "Found %s filters to resolve." % len(filter_set)
    return filter_set


def buildXMLpolicy(autnum, ipv4=True, ipv6=True):
    """ PreProcess section: Get own policy, parse and create necessary Data Structures """
    com = communicator.Communicator(ripe_db_url, default_db_source)
    pp = parsers.PolicyParser(autnum, ipv4, ipv6)

    pp.assignContent(com.getPolicyByAutnum(autnum))
    pp.readPolicy()

    """ Process section: Resolve necessary filters into prefixes """

    """ PostProcess: Create and deliver the corresponding XML output """
    xmlgen = xmlGenerator.xmlGenerator(autnum, ipv4, ipv6)
    xmlgen.convertPeersToXML(pp.peerings)
    return xmlgen.xml_policy

# ~~~ Script starts here ~~~

if len(sys.argv) < 2:
    print "\nIncomplete number of parameters. \n%s\n" % help_message

else:
    for arg in sys.argv:
        if arg == "-a":
            if tools.check_autnum_validity(sys.argv[sys.argv.index('-a') + 1]):
                params["as_number"] = sys.argv[sys.argv.index('-a') + 1].upper()
            else:
                print "Invalid aut-number"
                exit(1)
        if arg == "-o":
            params["output_file"] = sys.argv[sys.argv.index('-o') + 1]

        if arg == "-4":
            params["ipv4"] = "True"

        if arg == "-6":
            params["ipv6"] = "True"

        if arg == "-r":
            # for resolving AS-SETS, RS-SETS, FLTR-SETS etc
            params["resolve"] = "True"

print "Configuration done. Initialising..."

xml_result = buildXMLpolicy(params.get("as_number"))
# buildXMLpolicy(params.get("as_number"))

# if "output_file" in params:
#     f = open(params["output_file"], mode='w')
#     f.write(ET.tostring(xml_result, encoding='utf-8'))
#     f.close()
# else:
reparsed = parseString(ET.tostring(xml_result))
print reparsed.toprettyxml(indent="\t")

print "All done. XML policy is ready."
