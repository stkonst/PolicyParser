import sys
import logging
from xml.dom.minidom import parseString

import communicator
import parsers
import resolvers
import rpsl
import xmlGenerator

help_message = "Please run again by typing parser -a <ASXXX>"
params = dict()
black_list = set()

def read_blisted(as_list):
    items = set(as_list.split(","))
    for i in items:
        if not rpsl.is_ASN(i):
            print "{} is not a valid AS number".format(i)
            exit(1)
    return items


def buildXMLpolicy(autnum, ipv6=True, output='screen'):
    #
    # PreProcess section: Get own policy, parse and create necessary Data Structures.
    #
    com = communicator.Communicator()
    pp = parsers.PolicyParser(autnum)

    pp.assignContent(com.getPolicyByAutnum(autnum))
    pp.readPolicy()
    logging.debug("Found {} expressions to resolve.".format(pp.fltrExpressions.number_of_filters()))
    if pp.fltrExpressions.number_of_filters() < 1:
        print("No filter expressions found.")
        return None
    com.session.close()

    #
    # Process section: Resolve necessary fltrExpressions into prefixes.
    #
    fr = resolvers.filterResolver(pp.fltrExpressions, ipv6, black_list)
    fr.resolveFilters()

    #
    # PostProcess section: Create and deliver the corresponding XML output.
    #
    xmlgen = xmlGenerator.xmlGenerator(autnum)
    xmlgen.convertPeersToXML(pp.peerings)
    xmlgen.convertFiltersToXML(pp.fltrExpressions)
    xmlgen.convertListsToXML(fr.ASNList, fr.dataPool, fr.RSSetList, fr.RSSetDir, fr.ASSetList, fr.asSetdir)

    if output == "browser":
        return xmlgen.__str__()
    elif output == "screen":
        reparsed = parseString(xmlgen.__str__())
        return reparsed.toprettyxml(indent="\t")
    elif output == "file":
        return xmlgen.__str__()


# ~~~ Script starts here ~~~
if __name__ == "__main__":
    starting_flag = True
    if len(sys.argv) < 2:
        print "\nIncomplete number of parameters. \n{}\n".format(help_message)
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

            if arg == "-6":
                params["ipv6"] = "True"

            if arg == "-b":
                # Comma seperated list of AS numbers that we don't want to resolve (blacklisted)
                black_list = read_blisted(sys.argv[sys.argv.index('-b') + 1])

    print("Configuration done. Starting...")

    if starting_flag:
        logging.getLogger("requests").setLevel(logging.WARNING)
        if "output_file" in params:
            logging.basicConfig(filename=params["output_file"] + '.log', level=logging.DEBUG)
            xml_result = buildXMLpolicy(params.get("as_number"), output='file')
            if xml_result:
                f = open(params["output_file"], mode='w')
                f.write(xml_result)
                f.close()
        else:
            logging.basicConfig(level=logging.DEBUG)
            print buildXMLpolicy(params.get("as_number"), output='screen')

        logging.info("All done. XML policy is ready.")

    #def memory_usage():
    #    """http://stackoverflow.com/a/898406"""
    #    """Memory usage of the current process in kilobytes."""
    #    status = None
    #    result = {'peak': 0, 'rss': 0}
    #    try:
    #        # This will only work on systems with a /proc file system
    #        # (like Linux).
    #        status = open('/proc/self/status')
    #        for line in status:
    #            parts = line.split()
    #            key = parts[0][2:-1].lower()
    #            if key in result:
    #                result[key] = int(parts[1])
    #    finally:
    #        if status is not None:
    #            status.close()
    #    return result
    #print "Memory: {}".format(memory_usage())
