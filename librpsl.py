__author__ = 'stavros'
import sys
from xml.dom.minidom import parseString  # Will be removed
import xml.etree.ElementTree as et

import converter as PC
import communicator as fetcher
import libtools as tools


help_message = "Please run again by typing parser -a <ASXXX>"


def get_ripe_policy(autnum):
    return et.fromstring(fetcher.send_db_request(fetcher.locator_url_builder("aut-num", autnum)))


def build_xml_policy(autnum, ipv4=True, ipv6=True):
    # Init converter object
    policy_converter = PC.PolicyConverter(autnum, ipv4, ipv6)

    # Init new xml template
    policy_converter.init_xml_template()

    print "Resolving own policy (%s)" % autnum
    # Get the routes of the given Autonomous system
    policy_converter.xml_policy.find('./route-objects').append(
        policy_converter.get_routes_from_object(policy_converter.autnum))

    # Get the policy object of given Autonomous system from RIPE
    db_object = et.fromstring(fetcher.send_db_request(fetcher.locator_url_builder("aut-num", autnum)))

    # Extract the values from the policy RPSL object
    ases, filters = policy_converter.extract_rpsl_policy_(db_object)

    print "Will fetch routes for %s AS and %s filters " % (len(ases), len(filters))
    # Resolve unknown AS numbers
    for asnum in ases:
        # Get the routes of the given Autonomous system
        print "Resolving %s ..." % asnum
        try:
            policy_converter.xml_policy.find('./route-objects').append(
                policy_converter.get_routes_from_object(asnum))
        except:
            print "Failed to resolve %s" % asnum
            pass

    return policy_converter.xml_policy

# ~~~ Script starts here ~~~

as_number = ""
if len(sys.argv) < 2:
    print "\nIncomplete number of parameters. \n%s\n" % help_message

else:
    for arg in sys.argv:
        if arg == "-a":
            if tools.check_autnum_validity(sys.argv[sys.argv.index('-a') + 1]):
                as_number = sys.argv[sys.argv.index('-a') + 1]
            else:
                print "Invalid aut-number"
                exit(1)

print "Configuration done. Initialising..."
rough_string = et.tostring(build_xml_policy(as_number), 'utf-8')
reparsed = parseString(rough_string)
print "All done. XML policy is ready."
print reparsed.toprettyxml(indent="\t")