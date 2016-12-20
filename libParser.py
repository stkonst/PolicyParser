import logging
from xml.dom.minidom import parseString

import communicator
import parsers
import resolvers
import rpsl
import xmlGenerator
import yamlGenerator


def selector(rpsl_string, routes_only, ipv6=True, output_type='screen', black_list=set(), output_format="XML"):
    if not rpsl.is_ASN(rpsl_string):

        return build_simple_filter_output(rpsl_string, black_list, ipv6, output_type, output_format)

    else:
        # Looks like we have an AS number for input

        if routes_only:

            return build_simple_filter_output(rpsl_string, black_list, ipv6, output_type, output_format)

        else:
            #   Full policy resolving, go ahead then

            return build_full_policy_output(rpsl_string, ipv6=ipv6, output=output_type, black_list=black_list,
                                            policy_format=output_format)


def build_simple_filter_output(rpsl_string, black_list, ipv6, output_type, output_format):
    pd = rpsl.PeerFilterDir()
    pd.append_filter(rpsl.PeerFilter("", "", rpsl_string))

    fr = resolvers.FilterResolver(pd, ipv6, black_list)
    fr.resolve_filters()

    if output_format == "YAML":

        return _to_YAML(None, fr)
    else:

        return _to_XML("", None, fr, output_type)


def build_full_policy_output(autnum, ipv6=True, output='screen', black_list=set(), policy_format="XML"):
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
        return _to_YAML(pp, fr)

    else:
        return _to_XML(autnum, pp, fr, output)


def _to_YAML(pp, fr):
    yo = yamlGenerator.YamlGenerator()
    if fr:
        yo.convert_lists_to_dict(fr.AS_list, fr.AS_dir, fr.RS_list, fr.RS_dir,
                                 fr.AS_set_list, fr.AS_set_dir)
    if pp:
        yo.convert_filters_to_dict(pp.filter_expressions)
        yo.convert_peers_to_yaml(pp.peerings)
    return yo.print_policy()


def _to_XML(autnum, pp, fr, output):
    xmlgen = xmlGenerator.XmlGenerator(autnum)
    if pp:
        xmlgen.convert_peers_to_XML(pp.peerings)
        xmlgen.convert_filters_to_XML(pp.filter_expressions)
    if fr:
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


    def read_OBJECT(string):

        if rpsl.is_rs_set(string) or rpsl.is_pfx_filter(string) or rpsl.is_fltr_set(string):
            raise argparse.ArgumentTypeError("Unsupported type of Object. Expected ASN or AS-SET")

        if not (rpsl.is_ASN(string) or rpsl.is_AS_set(string)):
            raise argparse.ArgumentTypeError("Invalid Object '{}'. Expected AS<number> or AS-<value>"
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

    parser.add_argument('OBJECT', type=read_OBJECT,
                        help="It is either an autonomous System name in AS<number> format "
                             "or an AS-SET in AS-<value> format.")
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
    parser.add_argument('-r', '--routes_only', action="store_true",
                        help="Returns the route objects only that are related to the given AS number.")

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

        lib_result = selector(args.OBJECT, args.routes_only, output_type='file', black_list=args.blacklist,
                              output_format=args.format)
        if lib_result:
            with open(args.outputfile, mode='w') as f:
                f.write(lib_result)
    else:
        logging.basicConfig(level=logging_level)
        lib_result = selector(args.OBJECT, args.routes_only, output_type='screen', black_list=args.blacklist,
                              output_format=args.format)
        if lib_result:
            print "\n\n" + lib_result

    if lib_result:
        logging.info("All done. Output is ready.")
        print("All done. Output is ready.")
    else:
        logging.info("Failed to create the requested output. Check the logs for more "
                     "information.")
        print("Failed to create the requested output. Check the logs for more "
              "information.")
