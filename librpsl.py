__author__ = 'stavros'
import sys
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString

import converter as PC
import libtools as tools

help_message = "Please run again by typing parser -a <ASXXX>"
params = dict()


def collect_filters_from_peers(allpeers):
    filter_set = set()
    for val in allpeers.itervalues():
        filter_set.update(val.get_all_filters())

    print "Found %s filters to resolve." % len(filter_set)
    return filter_set


def build_xml_policy(autnum, ipv4=True, ipv6=True):

    policy_converter = PC.PolicyConverter(autnum, ipv4, ipv6)

    # Init new xml template
    policy_converter.init_xml_template()

    print "Resolving own policy (%s)" % autnum
    allpeers = policy_converter.extract_rpsl_policy(autnum)

    print "Convert peers to XML"
    policy_converter.convert_peers_toxml(allpeers)

    policy_filters = collect_filters_from_peers(allpeers)
    counter = 0
    for pfilter in policy_filters:
        # Get the routes/prefixes of the given filter
        counter += 1
        print "%s : " % (counter),
        if pfilter == "ANY" or pfilter == "any":
            print "\tSkipping any"
        else:
            print "Resolving %s... " % pfilter,
            try:
                policy_converter.parse_filter(pfilter)
                print "Done!"
            except:
                e = sys.exc_info()[0]
                print "\tFailed to resolve %s, Error: %s" % (pfilter, e)
                pass

    # print allpeers.keys()
    return policy_converter.xml_policy


# ~~~ Script starts here ~~~

if len(sys.argv) < 2:
    print "\nIncomplete number of parameters. \n%s\n" % help_message

else:
    for arg in sys.argv:
        if arg == "-a":
            if tools.check_autnum_validity(sys.argv[sys.argv.index('-a') + 1]):
                params["as_number"] = sys.argv[sys.argv.index('-a') + 1]
            else:
                print "Invalid aut-number"
                exit(1)
        if arg == "-o":
            params["output_file"] = sys.argv[sys.argv.index('-o') + 1]

        if arg == "-4":
            params["ipv4"] = "True"

        if arg == "-6":
            params["ipv6"] = "True"

print "Configuration done. Initialising..."

xml_result = build_xml_policy(params.get("as_number"))

if params.has_key("output_file"):
    f = open(params["output_file"], mode='w')
    f.write(ET.tostring(xml_result, encoding='utf-8'))
    f.close()
else:
    reparsed = parseString(ET.tostring(xml_result))
    print reparsed.toprettyxml(indent="\t")

print "All done. XML policy is ready."
