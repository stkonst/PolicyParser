__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
import sys
from xml.dom.minidom import parseString

import communicator
import rpsl
import parsers
import xmlGenerator
import libtools as tools

help_message = "Please run again by typing parser -a <ASXXX>"
ripe_db_url = "https://rest.db.ripe.net"
default_db_source = "ripe"
params = dict()


def buildXMLpolicy(autnum, ipv4=True, ipv6=True, output='screen'):
    """ PreProcess section: Get own policy, parse and create necessary Data Structures """
    com = communicator.Communicator(ripe_db_url, default_db_source)
    pp = parsers.PolicyParser(autnum, ipv4, ipv6)

    pp.assignContent(com.getPolicyByAutnum(autnum))
    pp.readPolicy()

    tools.d("Found %s filters to resolve" % pp.filters.number_of_filters())
    """ Process section: Resolve necessary filters into prefixes
        Use Multithreading to fetch necessary info from RIPE DB. """

    # count = round(pp.filters.number_of_filters() * 0.1)
    # last = pp.filters.number_of_filters() - (count*9)
    # print "Per thread: %s, Last thread: %s" % (count, last)
    ' TODO: Implement multi-threading to resolve filters'

    #
    #
    #

    """ PostProcess: Create and deliver the corresponding XML output """
    xmlgen = xmlGenerator.xmlGenerator(autnum, ipv4, ipv6)
    xmlgen.convertPeersToXML(pp.peerings)
    xmlgen.convertFiltersToXML(pp.filters)

    if output == "browser":
        return xmlgen.__str__()
    elif output == "screen":
        reparsed = parseString(xmlgen.__str__())
        return reparsed.toprettyxml(indent="\t")
    elif output == "file":
        return xmlgen.__str__()

# ~~~ Script starts here ~~~

starting_flag = True
if len(sys.argv) < 2:
    print "\nIncomplete number of parameters. \n%s\n" % help_message
    starting_flag = False

else:
    for arg in sys.argv:
        if arg == "-a":
            if rpsl.check_autnum_validity(sys.argv[sys.argv.index('-a') + 1]):
                params["as_number"] = sys.argv[sys.argv.index('-a') + 1].upper()
            else:
                print "Invalid aut-number"
                starting_flag = False
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

if starting_flag:

    if "output_file" in params:
        xml_result = buildXMLpolicy(params.get("as_number"), output='file')
        f = open(params["output_file"], mode='w')
        f.write(xml_result)
        f.close()
    else:
        print buildXMLpolicy(params.get("as_number"), output='screen')

    print "All done. XML policy is ready."
