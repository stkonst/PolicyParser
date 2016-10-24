import logging
from xml.dom.minidom import parseString

import communicator
import parsers
import resolvers
import rpsl
import xmlGenerator
import yamlGenerator


def build_policy(autnum, ipv6=True, output='screen', black_list=set(), policy_format="XML"):
    #
    # PreProcess section: Get own policy, parse and create necessary Data
    #                     Structures.
    #
    com = communicator.Communicator()
    pp = parsers.PolicyParser(autnum)

    pp.assign_content(com.get_policy_by_autnum(autnum))
    pp.read_policy()
    logging.debug("Expressions to resolve: "
                  "{}".format(pp.filter_expressions.number_of_filters()))
    if pp.filter_expressions.number_of_filters() < 1:
        print("No filter expressions found.")
        com.session.close()
        return None
    com.session.close()

    #
    # Process section: Resolve necessary filter_expressions into prefixes.
    #
    fr = resolvers.FilterResolver(pp.filter_expressions, ipv6, black_list)
    fr.resolve_filters()

    #
    # PostProcess section: Create and deliver the corresponding output.
    #
    if policy_format == "YAML":
        yo = yamlGenerator.YamlGenerator()
        yo.convert_lists_to_dict(fr.AS_list, fr.AS_dir, fr.RS_list, fr.RS_dir,
                                 fr.AS_set_list, fr.AS_set_dir)
        yo.convert_filters_to_dict(pp.filter_expressions)
        yo.convert_peers_to_yaml(pp.peerings)
        return yo.print_policy()

    else:
        xmlgen = xmlGenerator.XmlGenerator(autnum)
        xmlgen.convert_peers_to_XML(pp.peerings)
        xmlgen.convert_filters_to_XML(pp.filter_expressions)
        xmlgen.convert_lists_to_XML(fr.AS_list, fr.AS_dir, fr.RS_list, fr.RS_dir,
                                    fr.AS_set_list, fr.AS_set_dir)

        if output == "browser":
            return str(xmlgen)
        elif output == "screen":
            reparsed = parseString(str(xmlgen))
            return reparsed.toprettyxml(indent="\t")
        elif output == "file":
            return str(xmlgen)


if __name__ == "__main__":
    import argparse


    def read_ASN(string):
        if not rpsl.is_ASN(string):
            raise argparse.ArgumentTypeError("Invalid ASN '{}'. Expected "
                                             "format: AS<number>"
                                             .format(string))
        return string


    def read_file(string):
        return string.lower()


    def read_blacklisted(string):
        items = set(string.split(","))
        for i in items:
            if not rpsl.is_ASN(i):
                raise argparse.ArgumentTypeError("Invalid ASN '{}'. Expected "
                                                 "format: AS<number>"
                                                 .format(i))
        return items


    def read_format(string):
        if string in ['YAML', 'yaml']:
            return "YAML"
        else:
            return "XML"


    parser = argparse.ArgumentParser()
    parser.add_argument('ASN', type=read_ASN,
                        help="Autonomous System name in AS<number> format.")
    parser.add_argument('-o', '--outputfile', type=read_file,
                        help="Name of the output file produced. An additional "
                             ".log file will also be created.")
    parser.add_argument('-b', '--blacklist', type=read_blacklisted,
                        help="A comma separated list of AS numbers that can "
                             "be excluded from the resolving.",
                        default=set())
    parser.add_argument('-d', '--debug', action="store_true",
                        help="Log additional debugging information.")
    parser.add_argument('-f', '--format', type=read_format,
                        help="Select the format of the output file. It can be either XML (default) or YAML.")

    args = parser.parse_args()
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.WARNING
    print("Configuration done. Starting...")

    logging.getLogger("requests").setLevel(logging.WARNING)
    if args.outputfile:

        if not args.outputfile.endswith('.xml') or not args.outputfile.endswith('.yaml'):
            if args.format == "YAML":
                args.outputfile += '.yaml'
            else:
                args.outputfile += '.xml'

        logging.basicConfig(filename=args.outputfile + '.log', filemode="w",
                            level=logging_level)
        policy_result = build_policy(args.ASN, output='file',
                                     black_list=args.blacklist, policy_format=args.format)
        if policy_result:
            with open(args.outputfile, mode='w') as f:
                f.write(policy_result)
    else:
        logging.basicConfig(level=logging_level)
        policy_result = build_policy(args.ASN, output='screen',
                                     black_list=args.blacklist, policy_format=args.format)
        if policy_result:
            print(policy_result)

    if policy_result:
        logging.info("All done. Converted policy is ready.")
        print("All done. Converted policy is ready.")
    else:
        logging.info("Converted policy was not created. Check the logs for more "
                     "information.")
        print("Converted policy was not created. Check the logs for more "
              "information.")
