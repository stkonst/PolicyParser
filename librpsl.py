__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
import sys
import logging
from xml.dom.minidom import parseString

import communicator
import rpsl
import parsers
import resolvers
import xmlGenerator

help_message = "Please run again by typing parser -a <ASXXX>"
ripe_db_url = "https://rest.db.ripe.net"
default_db_source = "ripe"
alternative_db_sources = ("RADB-GRS", "APNIC-GRS", "ARIN-GRS", "LACNIC-GRS", "AFRINIC-GRS")
params = dict()


def buildXMLpolicy(autnum, ipv4=True, ipv6=True, output='screen'):

    """ PreProcess section: Get own policy, parse and create necessary Data Structures """
    com = communicator.Communicator(ripe_db_url, default_db_source, alternative_db_sources)
    pp = parsers.PolicyParser(autnum, ipv4, ipv6)

    pp.assignContent(com.getPolicyByAutnum(autnum))
    pp.readPolicy()
    logging.debug("Found %s expressions to resolve" % pp.fltrExpressions.number_of_filters())

    """ Process section: Resolve necessary fltrExpressions into prefixes
        Maybe use Multithreading to fetch necessary info from RIPE DB. """
    ' TODO: Implement multi-threading to resolve fltrExpressions'
    fr = resolvers.filterResolver(pp.fltrExpressions, com, ipv6)
    fr.resolveFilters()

    """ PostProcess: Create and deliver the corresponding XML output """
    com.session.close()
    xmlgen = xmlGenerator.xmlGenerator(autnum, ipv4, ipv6)
    xmlgen.convertPeersToXML(pp.peerings)
    xmlgen.convertFiltersToXML(pp.fltrExpressions)

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
            if rpsl.is_ASN(sys.argv[sys.argv.index('-a') + 1]):
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

print("Configuration done. Initialising...")

if starting_flag:
    logging.getLogger("requests").setLevel(logging.WARNING)
    if "output_file" in params:
        logging.basicConfig(filename=params["output_file"] + '.log', level=logging.DEBUG)
        xml_result = buildXMLpolicy(params.get("as_number"), output='file')
        f = open(params["output_file"], mode='w')
        f.write(xml_result)
        f.close()
    else:
        logging.basicConfig(level=logging.DEBUG)
        print buildXMLpolicy(params.get("as_number"), output='screen')

    logging.info("All done. XML policy is ready.")
