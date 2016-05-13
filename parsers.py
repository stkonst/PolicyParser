import logging
import re
try:
    from cStringIO import StringIO
except ImportError:
    logging.warning("cStringIO was not available! Expect the execution time"
                    " and memory consumption to go up!")
    from StringIO import StringIO
try:
    import xml.etree.cElementTree as et
except ImportError:
    logging.warning("cElementTree was not available! Expect the execution time"
                    " and memory consumption to go up!")
    import xml.etree.ElementTree as et

import xxhash

import errors
import libtools as tools
import rpsl


# Start of Tomas' expressions for parsers.
FACTOR_SPLIT_ACCEPT = 'ACCEPT'  # regexp would be better but slower
FACTOR_SPLIT_ANNOUNCE = 'ANNOUNCE'  # regexp would be better but slower
FACTOR_SPLIT_NETWORKS = 'NETWORKS'  # regexp would be better but slower
FACTOR_CONST_ACCEPT = 'ACCEPT'
FACTOR_CONST_ANNOUNCE = 'ANNOUNCE'
FACTOR_CONST_NETWORKS = 'NETWORKS'
FACTOR_SPLIT_FROM = re.compile('^(|.*\s+)FROM\s+', re.I)
FACTOR_SPLIT_TO = re.compile('^(|.*\s+)TO\s+', re.I)
AFI_MATCH = re.compile('^AFI\s+([^\s]+)\s+(.*)$', re.I)
PARSE_RANGE = re.compile('^\^([0-9]+)-([0-9]+)$', re.I)
################# HACK HACK HACK
AFI_MATCH_HACK = re.compile('^AFI\s+(IPV6.UNICAST)(FROM.*)$', re.I)
################# END OF HACK

IMPORT_FACTOR_MATCH = re.compile('^FROM\s+([^\s]+)(\s?(.*)\sACCEPT(.+))$', re.I)
EXPORT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s?(.*)\sANNOUNCE(.+))$', re.I)
DEFAULT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s?(.*)\sNETWORKS(.+)|.*)$', re.I)
# End of Tomas' expressions for parsers.

ACTION_RESHAPE = re.compile(r'\s|[{\s*|\s*}]')
ACTION_COMMUNITY_APPEND = re.compile('\.(?:append|=)[{(]([^)}]*)[)}]', re.I)
ACTION_COMMUNITY_DELETE = re.compile('delete\((.*)\)', re.I)
ACTION_ASPATH_PREPEND = re.compile('prepend\((.*)\)', re.I)

EXTRACT_ACTIONS_EXPORT = re.compile('ACTION(.*)ANNOUNCE', re.I)
EXTRACT_ACTIONS_IMPORT = re.compile('ACTION(.*)ACCEPT', re.I)

IP_EXTRACT_RE = re.compile("(?P<afi>AFI\s\w*\.\w*)?\s?(FROM|TO)\sAS(?:\d+)\s(?P<remote>\S+)?\s?AT?\s?(?P<local>\S+)?\s", re.I)
FIND_IP_FACTOR1 = re.compile("AS(?:\d+)\s(?P<something>.*)\s?(?:accept|announce)\s", re.I)
FIND_IP_FACTOR2 = re.compile("AS(?:\d+)\s(?P<something>.*)\s?(?:action)\s", re.I)


class PolicyParser:
    def __init__(self, autnum):
        self.et_content = et.ElementTree()
        self.autnum = autnum
        self.peerings = rpsl.PeerObjDir()
        self.filter_expressions = rpsl.PeerFilterDir()

    def assign_content(self, xml_text):
        try:
            self.et_content = et.fromstring(xml_text)
        except et.ParseError, et.TypeError:
            raise Exception('Failed to load DB content in XML format')

    def read_policy(self):
        """Retrieves the imports/exports of the policy and passes them to the
        interpreter.
        """
        logging.debug('Will parse policy for {}'.format(self.autnum))
        for elem in self.et_content.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):
            if "import" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(),
                                     mp=False, rule_type="import")

                except errors.InterpreterError:
                    logging.error("Failed to parse import "
                                  "[{}]".format(elem.attrib.get("value")))

            elif "export" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(),
                                     mp=False, rule_type="export")

                except errors.InterpreterError:
                    logging.error("Failed to parse export "
                                  "[{}]".format(elem.attrib.get("value")))

            elif "mp-import" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(),
                                     mp=True, rule_type="import")

                except errors.InterpreterError:
                    logging.error("Failed to parse mp-import "
                                  "[{}]".format(elem.attrib.get("value")))

            elif "mp-export" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(), mp=True,
                                     rule_type="export")

                except errors.InterpreterError:
                    logging.error("Failed to parse mp-export "
                                  "[{}]".format(elem.attrib.get("value")))

    def extract_IPs(self, policy_object, peering_point, mp=False):
        """NOTICE: RPSL Allows also 1 out of the 2 IPs to exist."""

        items = re.search(IP_EXTRACT_RE, policy_object)

        try:
            l, r = "", ""
            if items.group("remote") is not None:
                if tools.is_valid_ipv4(items.group("remote")):
                    r = str(items.group("remote"))
                elif tools.is_valid_ipv6(items.group("remote")):
                    r = str(items.group("remote"))

            if items.group("local") is not None:
                if tools.is_valid_ipv4(items.group("local")):
                    l = str(items.group("local"))
                elif tools.is_valid_ipv6(items.group("local")):
                    l = str(items.group("local"))

            peering_point.append_addresses(l, r)

        except:
            raise errors.IPparseError("Failed to parse IP values")

    def extract_actions(self, line, policy_action_list, export=False):
        """Discovers and extracts the actions from an rpsl expression. Then
        creates actions lists and appends the actions with their values.
        """
        if export:
            actions = filter(None, re.search(EXTRACT_ACTIONS_EXPORT, line).group(1).replace(" ", "").split(";"))
        else:
            actions = filter(None, re.search(EXTRACT_ACTIONS_IMPORT, line).group(1).replace(" ", "").split(";"))

        try:
            for i, action in enumerate(actions):

                if 'COMMUNITY' in action:
                    val = re.search(ACTION_COMMUNITY_APPEND, action).group(1)
                    if val is not None:
                        if "," in val:
                            # Multiple values of community may exist
                            mval = val.split(",")
                            for c in mval:
                                p_action = rpsl.PolicyAction(i, "community",
                                                             "append", c)
                                policy_action_list.append_action(p_action)
                        else:
                            p_action = rpsl.PolicyAction(i, "community",
                                                         "append", val)
                            policy_action_list.append_action(p_action)
                    else:
                        val = re.search(ACTION_COMMUNITY_DELETE, action).group(1)
                        if val is not None:
                            if "," in val:
                                # Multiple values of community may exist
                                mval = val.split(",")
                                for c in mval:
                                    p_action = rpsl.PolicyAction(i, "community",
                                                                 "delete", c)
                                    policy_action_list.append_action(p_action)
                            else:
                                p_action = rpsl.PolicyAction(i, "community",
                                                             "delete", val)
                                policy_action_list.append_action(p_action)
                elif 'ASPATH' in action:
                    val = re.search(ACTION_ASPATH_PREPEND, action).group(1)
                    p_action = rpsl.PolicyAction(i, "aspath", "prepend", val)
                    policy_action_list.append_action(p_action)
                else:
                    elements = action.split("=")
                    p_action = rpsl.PolicyAction(i, elements[0], "=",
                                                 elements[1])
                    policy_action_list.append_action(p_action)
        except:
            raise errors.ActionParseError("Failed to parse actions "
                                          "{}".format(actions))

    def decompose_expression(self, text, default_rule=False):
        def _get_first_group(text):
            brc = 0  # brace count
            gotgroup = False

            for i, c in enumerate(text):
                if c == '{':
                    if i == 0:
                        gotgroup = True
                    brc += 1
                if c == '}':
                    brc -= 1

                if gotgroup and brc == 0:
                    return text[1:i].strip()

                beg = text[i:]
                if beg.startswith('REFINE') or beg.startswith('EXCEPT'):
                    return text[:i - 1].strip()
            else:
                if brc != 0:
                    raise Exception("Brace count does not fit in rule: " + text)
                else:
                    return text.strip()

        # Split the line to { factor1; factor2; ... } and the rest
        # (refinements etc).
        e = _get_first_group(text.strip())

        # defaults for rules like: export: default to AS1234
        sel = e
        fltr = ''

        # regexps would be better but slower
        if e.find(FACTOR_SPLIT_ACCEPT) > -1:
            [sel, fltr] = e.split(FACTOR_SPLIT_ACCEPT, 1)
            fltr = (FACTOR_CONST_ACCEPT + ' ' + fltr.strip())
        elif e.find(FACTOR_SPLIT_ANNOUNCE) > -1:
            [sel, fltr] = e.split(FACTOR_SPLIT_ANNOUNCE, 1)
            fltr = (FACTOR_CONST_ANNOUNCE + ' ' + fltr.strip())
        elif e.find(FACTOR_SPLIT_NETWORKS) > -1:
            [sel, fltr] = e.split(FACTOR_SPLIT_NETWORKS, 1)
            fltr = (FACTOR_CONST_NETWORKS + ' ' + fltr.strip())
        else:
            if default_rule:  # default: rule does not need to include filter, then default to ANY
                fltr = 'ANY'
            else:
                logging.warning("Syntax error: Can not find selectors in: "
                                "{} decomposing expression: {}".format(e, text))
                # raise Exception("Can not find selectors in: "+e)

        # here regexps are necessary
        if len(FACTOR_SPLIT_FROM.split(sel)) > 2:
            return ([str('FROM ' + f.strip()) for f in FACTOR_SPLIT_FROM.split(sel)[2:]], fltr)

        elif len(FACTOR_SPLIT_TO.split(sel)) > 2:
            return ([str('TO ' + f.strip()) for f in FACTOR_SPLIT_TO.split(sel)[2:]], fltr)

        else:
            # TODO: make it custom error
            raise Exception("Can not find filter factors in: "
                            "'{}' in text: {}".format(sel, text))

    def normalize_factor(self, selector, fltr):
        """Returns (subject, filter) where subject is AS or AS-SET and
        filter is a filter. For example in factor:
        "to AS1234 announce AS-SECRETNET" : the subject is AS1234 and
        the filter is the AS-SECRETNET; the same for factor:
        "from AS1234 accept ANY": the subject is AS1234 and the filter
        is ANY and the same for default factors like the following:
        "to AS1234 networks ANY"
        """

        factor = (selector + ' ' + fltr).strip()
        if factor[-1] == ';':
            factor = factor[:-1].strip()

        m = IMPORT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),
                    (m.group(4).strip() if m.group(4) else 'ANY'))

        m = EXPORT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),
                    (m.group(4).strip() if m.group(4) else 'ANY'))

        m = DEFAULT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),
                    (m.group(4).strip() if m.group(4) else 'ANY'))

        raise Exception("Can not parse factor: " + factor)

    def parse_rule(self, rule, direction, mp):
        """Returns (afi, [(subject, filter)]). Remove all refine and except
        blocks as well as protocol and to specs.

        The (subject, filter) are taken from factors where subject is
        AS or AS-SET and filter is a filter string. For example in factor:
        "to AS1234 announce AS-SECRETNET" : the subject is AS1234 and
        the filter is the AS-SECRETNET; the same for factor:
        "from AS1234 accept ANY": the subject is AS1234 and the filter
        is ANY.

        afi is by default ipv4.unicast. For MP rules it is being parsed and
        filled in according to the rule content.
        """
        afi = 'IPV4.UNICAST'

        if mp:
            r = AFI_MATCH.match(rule)
            ############# HACK HACK HACK !!! fix of a syntax error in RIPE DB in object
            ############# aut-num AS2852 (cesnet) that contains weird line with merged
            ############# afi spec and
            rh = AFI_MATCH_HACK.match(rule)
            if rh:
                r = rh
            ############# END OF HACK

            if r:
                afi = r.group(1)
                rule = r.group(2)
            else:
                afi = 'ANY'

        factors = self.decompose_expression(rule)

        return (direction, afi,
                [self.normalize_factor(f, factors[1]) for f in factors[0]])

    def interpreter(self, rule, rule_type, mp=False):
        """Analyse and interpret the rule_type.

        subject = AS that is announcing the prefix to or as that the prefix is
                  exported to by the AS that conains this rule_type.
        prefix = prefix that is in question.
        currentAsPath = aspath as it is (most likely) seen by the AS.
        assetDirectory = HashObjectDir that conains the AsSetObjects.
        fltrsetDirectory = HashObjectDir that conains the FilterSetObjects.
        rtsetDirectory = HashObjectDir that conains the RouteSetObjects.
        ipv6 = matching IPv6 route?
        """

        if "REFINE" in rule:
            raise errors.InterpreterError("REFINE is not currently supported")
            return

        res = self.parse_rule(rule, rule_type, mp)  # return (direction, afi, [(subject, filter)])

        try:
            peer_as = self.peerings.return_peering(res[2][0][0])
        except errors.ASDiscoveryError:
            peer_as = rpsl.PeerAS(res[2][0][0])

        # Separation of roles. The peer class will get a pointer to the filter
        # (hash value) while the real filter will be stored temporarily for the
        # second round of resolving.

        if res[2][0][1] != 'ANY':
            # Create a hash of the filter expression
            ha = str(xxhash.xxh64(res[2][0][1]).hexdigest())

            # The actual peer filter is constructed and stored here.
            pf = rpsl.PeerFilter(ha, res[1], res[2][0][1])
            self.filter_expressions.append_filter(pf)

            # Append in the peer the filter set(direction, afi, hash)
            try:
                peer_as.append_filter((res[0], res[1], ha), mp)  # !!!!!!!!!!!!! TODO: Try to find what the '!'s mean.
            except errors.AppendFilterError:
                # logging.warning("Failed to append filter %s on peer %s" % (ha, peer_as.origin))
                raise errors.InterpreterError("Failed to append filter for "
                                              "peer {}.".format(peer_as.origin))

        pp = rpsl.PeeringPoint()

        # check if optional action(s) exist
        action_exists = False
        if " ACTION " in rule:
            action_exists = True
            if rule_type is "import":
                pal = rpsl.PolicyActionList(direction="import")
                try:
                    self.extract_actions(rule, pal)
                    pp.actions_in = pal
                except errors.ActionParseError:
                    logging.error("Failed to parse import actions")
                    pass
            else:
                pal = rpsl.PolicyActionList(direction="export")
                try:
                    self.extract_actions(rule, pal, export=True)
                    pp.actions_out = pal
                except errors.ActionParseError:
                    logging.error("Failed to parse export actions")
                    pass

        if action_exists:
            possible_ips = re.search(FIND_IP_FACTOR2, rule)
        else:
            possible_ips = re.search(FIND_IP_FACTOR1, rule)
            # XXX === WARNING ===
            #    In case of peering on multiple network edges,
            #    more peering-IPs are present in the policy!!!
        if possible_ips and len(possible_ips.group("something")) > 2:
            try:
                self.extract_IPs(rule, pp, mp)
                if peer_as.check_peering_point_key(pp.get_key()):
                    pp = peer_as.return_peering_point(pp.get_key())
            except errors.IPparseError as e:
                logging.error(str(e))
                pass

        peer_as.append_peering_point(pp)
        self.peerings.append_peering(peer_as)


def parse_AS_routes(xml_resp, ipv4=True, ipv6=True):
    """Parses the XML response in-place and returns the ipv4/ipv6 routes."""
    routes = {'ipv4': set(), 'ipv6': set()}
    try:
        xml_resp = StringIO(xml_resp)
        context = et.iterparse(xml_resp, events=('start', 'end'))
        context = iter(context)
        _, root = context.next()
        in_primary_key = False
        for event, elem in context:
            if event == 'start' and elem.tag == 'primary-key':
                in_primary_key = True
            elif event == 'end':
                if elem.tag == 'attribute' and in_primary_key:
                    continue
                elif elem.tag == 'primary-key':
                    for child_elem in elem:
                        if ipv4 and child_elem.attrib.get('name') == 'route':
                            route = child_elem.attrib.get('value')
                            routes['ipv4'].add(route)
                        elif ipv6 and child_elem.attrib.get('name') == 'route6':
                            route = child_elem.attrib.get('value')
                            routes['ipv6'].add(route)
                    in_primary_key = False
                # Keeps the generated tree empty.
                elem.clear()
                root.clear()
    finally:
        xml_resp.close()

    return routes


def parse_AS_set_members(xml_resp):
    """Parses the XML response and returns the AS set's members."""
    db_object = et.fromstring(xml_resp)
    AS_sets = set()
    ASNs = set()
    for elem in db_object.iterfind('./objects/object[@type="as-set"]/attributes'):
        for subelem in elem.iterfind('./attribute[@name="members"]'):
            val = subelem.attrib.get("value")
            if rpsl.is_ASN(val):
                ASNs.add(val)
            elif rpsl.is_AS_set(val):
                AS_sets.add(val)
    return AS_sets, ASNs


def parse_RS_members(xml_resp, ipv4=True, ipv6=True):
    """Parses the XML response in-place and returns the RS' members."""
    RSes = set()
    routes = {'ipv4': set(), 'ipv6': set()}

    try:
        xml_resp = StringIO(xml_resp)
        context = et.iterparse(xml_resp, events=('start', 'end'))
        context = iter(context)
        _, root = context.next()
        for event, elem in context:
            if event == 'end':
                if elem.tag == 'attribute' and elem.attrib.get('name'):
                    if (elem.attrib.get('name') == 'members' or
                            elem.attrib.get('name') == 'mp-members'):
                        member = elem.attrib.get('value')
                        # XXX The following should be used instead but change needs time
                        # if rpsl.is_rs_set_with_range(member):
                        if rpsl.is_rs_set(member):
                            RSes.add(member)
                        elif ipv4 and tools.is_valid_ipv4_with_range(member):
                            routes['ipv4'].add(member)
                        elif ipv6 and tools.is_valid_ipv6_with_range(member):
                            routes['ipv6'].add(member)

                # Keeps the generated tree empty.
                elem.clear()
                root.clear()
    finally:
        xml_resp.close()

    return RSes, routes
