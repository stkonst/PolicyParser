__author__ = 'stavros'
import sys
from xml.dom.minidom import parseString  # Will be removed
import xml.etree.ElementTree as et

import converter as PC
import libtools as tools


help_message = "Please run again by typing parser -a <ASXXX>"
params = dict()


def build_xml_policy(autnum, ipv4=True, ipv6=True):
    # Init converter object
    policy_converter = PC.PolicyConverter(autnum, ipv4, ipv6)

    # Init new xml template
    policy_converter.init_xml_template()

    print "Resolving own policy (%s)" % autnum
    # Get the routes of the given Autonomous system
    policy_converter.xml_policy.find('./route-objects').append(
        policy_converter.get_routes_from_object(policy_converter.autnum))

    # Extract the values from the policy RPSL object
    ases, filters = policy_converter.extract_rpsl_policy(autnum)

    print "Will fetch routes for %s AS and %s filters " % (len(ases), len(filters))
    for asnum in ases:
        # Get the routes of the given Autonomous system
        print "Resolving %s ..." % asnum
        try:
            policy_converter.xml_policy.find('./route-objects').append(
                policy_converter.get_routes_from_object(asnum))
        except:
            e = sys.exc_info()[0]
            print "Failed to resolve %s, Error: %s" % (asnum, e)
            pass

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

rough_string = et.tostring(build_xml_policy(params.get("as_number")))
reparsed = parseString(rough_string)

if params["output_file"]:
    f = open(params["output_file"], mode='w')
    f.write(reparsed.toprettyxml(indent="\t"))
    f.close()
else:
    print reparsed.toprettyxml(indent="\t")
print "All done. XML policy is ready."
