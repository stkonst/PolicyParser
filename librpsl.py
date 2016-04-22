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


def read_blisted(AS_list):
    items = set(AS_list.split(","))
    for i in items:
        if not rpsl.is_ASN(i):
            print "{} is not a valid AS number".format(i)
            exit(1)
    return items


def build_XML_policy(autnum, ipv6=True, output='screen'):
    #
    # PreProcess section: Get own policy, parse and create necessary Data Structures.
    #
    com = communicator.Communicator()
    pp = parsers.PolicyParser(autnum)

    pp.assign_content(com.get_policy_by_autnum(autnum))
    pp.read_policy()
    logging.debug("Found {} expressions to resolve.".format(pp.filter_expressions.number_of_filters()))
    if pp.filter_expressions.number_of_filters() < 1:
        print("No filter expressions found.")
        return None
    com.session.close()

    #
    # Process section: Resolve necessary filter_expressions into prefixes.
    #
    fr = resolvers.FilterResolver(pp.filter_expressions, ipv6, black_list)
    fr.resolve_filters()

    #
    # PostProcess section: Create and deliver the corresponding XML output.
    #
    xmlgen = xmlGenerator.XmlGenerator(autnum)
    xmlgen.convert_peers_to_XML(pp.peerings)
    xmlgen.convert_filters_to_XML(pp.filter_expressions)
    xmlgen.convert_lists_to_XML(fr.AS_list, fr.AS_dir, fr.RS_list, fr.RS_dir, fr.AS_set_list, fr.AS_set_dir)

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
            xml_result = build_XML_policy(params.get("as_number"), output='file')
            if xml_result:
                f = open(params["output_file"], mode='w')
                f.write(xml_result)
                f.close()
        else:
            logging.basicConfig(level=logging.DEBUG)
            print build_XML_policy(params.get("as_number"), output='screen')

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
