__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com)'
import logging
import xml.etree.ElementTree as et
import re
import xxhash

import libtools as tools
import errors
import rpsl

''' Start of Tomas' expressions for parsers '''
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

''' End of Tomas' expressions for parsers '''

ACTION_RESHAPE = re.compile(r'\s|[{\s*|\s*}]')
ACTION_COMMUNITY_APPEND = re.compile('\.(?:append|=)[{(]([^)}]*)[)}]', re.I)
ACTION_COMMUNITY_DELETE = re.compile('delete\((.*)\)', re.I)
ACTION_ASPATH_PREPEND = re.compile('prepend\((.*)\)', re.I)

EXTRACT_ACTIONS_EXPORT = re.compile('ACTION(.*)ANNOUNCE', re.I)
EXTRACT_ACTIONS_IMPORT = re.compile('ACTION(.*)ACCEPT', re.I)
# EXTACT_IPS_V4 = re.compile('\s\w*\s([0-9\.]+)\sAT?\s?([0-9\.]*)', re.I)
# EXTACT_IPS_V6 = re.compile('\s\w*\s([0-9a-z:]+)\sAT?\s?([0-9a-z:]*)', re.I)
IP_EXTRACT_RE = re.compile("(?P<afi>AFI\s\w*\.\w*)?\s?(FROM|TO)\sAS(?:\d*)\s(?P<remote>\S*)\sAT\s(?P<local>\S*)", re.I)


class PolicyParser:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.etContent = et.ElementTree()
        self.autnum = autnum
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6
        self.peerings = rpsl.PeerObjDir()
        self.fltrExpressions = rpsl.peerFilterDir()

    def assignContent(self, xmltext):
        try:
            self.etContent = et.fromstring(xmltext)
        except et.ParseError:
            raise Exception('Failed to load DB content in XML format')

    def readPolicy(self):

        logging.debug('Will parse policy for %s' % self.autnum)
        for elem in self.etContent.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):
            if "import" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(), mp=False, rule="import")

                except:
                    "TODO: Catch a custom error"
                    logging.warning("Failed to parse import {%s}" % elem.attrib.get("value"))
                    pass

            elif "export" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(), mp=False, rule="export")

                except:
                    "TODO: Catch a custom error"
                    logging.warning("Failed to parse export {%s}" % elem.attrib.get("value"))
                    pass

            elif "mp-import" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(), mp=True, rule="import")

                except:
                    "TODO: Catch a custom error"
                    logging.warning("Failed to parse mp-import {%s}" % elem.attrib.get("value"))
                    pass

            elif "mp-export" == elem.attrib.get("name"):
                try:
                    self.interpreter(elem.attrib.get("value").upper(), mp=True, rule="export")

                except:
                    "TODO: Catch a custom error"
                    logging.warning("Failed to parse mp-export {%s}" % elem.attrib.get("value"))
                    pass

    def extractIPs(self, policy_object, PeeringPoint, mp=False):
        """ RPSL Allows also 1 out of the 2 IPs to exist. """

        items = re.search(IP_EXTRACT_RE, policy_object)

        if tools.is_valid_ipv4(items.group("remote")):
            if tools.is_valid_ipv4(items.group("local")):
                PeeringPoint.appendAddresses(items.group("local"), items.group("remote"))
            else:
                logging.warn("Invalid IPv4 detected/extracted")
                return
        elif tools.is_valid_ipv6(items.group("remote")):
            if tools.is_valid_ipv6(items.group("local")):
                PeeringPoint.appendAddresses(items.group("local"), items.group("remote"))
            else:
                logging.warn("Invalid IPv6 detected/extracted")
                return
        else:
            raise errors.IPparseError("Failed to parse IP values")

    def extractActions(self, line, PolicyActionList, export=False):
        if export:
            actions = filter(None, re.search(EXTRACT_ACTIONS_EXPORT, line).group(1).strip(" ").split(";"))
        else:
            actions = filter(None, re.search(EXTRACT_ACTIONS_IMPORT, line).group(1).strip(" ").split(";"))

        for i, action in enumerate(actions):

            if 'community' in action:
                val = re.search(ACTION_COMMUNITY_APPEND, action).group(1)
                if val is not None:
                    PolicyActionList.appendAction(rpsl.PolicyAction(i, "community", "append", val))
                else:
                    val = re.search(ACTION_COMMUNITY_DELETE, action).group(1)
                    PolicyActionList.appendAction(rpsl.PolicyAction(i, "community", "delete", val))
            elif 'aspath' in action:
                val = re.search(ACTION_ASPATH_PREPEND, action).group(1)
                PolicyActionList.appendAction(rpsl.PolicyAction(i, "aspath", "prepend", val))
            else:
                elements = action.split("=")
                PolicyActionList.appendAction(rpsl.PolicyAction(i, elements[0], "=", elements[1]))

    def decomposeExpression(self, text, defaultRule=False):
        def _getFirstGroup(text):
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
                    "TODO: Make it custom error"
                    raise Exception("Brace count does not fit in rule: " + text)
                else:
                    return text.strip()

        # split line to { factor1; factor2; ... } and the rest (refinements etc)
        e = _getFirstGroup(text.strip())

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
            if defaultRule:  # default: rule does not need to include filter, then default to ANY
                fltr = 'ANY'
            else:
                logging.warning("Syntax error: Can not find selectors in:", e, "decomposing expression:", text)
                # raise Exception("Can not find selectors in: "+e)

        # here regexps are necessary
        if len(FACTOR_SPLIT_FROM.split(sel)) > 2:
            return ([str('FROM ' + f.strip()) for f in FACTOR_SPLIT_FROM.split(sel)[2:]], fltr)

        elif len(FACTOR_SPLIT_TO.split(sel)) > 2:
            return ([str('TO ' + f.strip()) for f in FACTOR_SPLIT_TO.split(sel)[2:]], fltr)

        else:
            "TODO: make it custom error"
            raise Exception("Can not find filter factors in: '" + sel + "' in text: " + text)

    def normalizeFactor(self, selector, fltr):
        """
        Returns (subject, filter) where subject is AS or AS-SET and
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
            return (m.group(1).strip(), (m.group(4).strip() if m.group(4) else 'ANY'))

        m = EXPORT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(), (m.group(4).strip() if m.group(4) else 'ANY'))

        m = DEFAULT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(), (m.group(4).strip() if m.group(4) else 'ANY'))

        raise Exception("Can not parse factor: " + factor)

    def parseRule(self, mytext, direction, mp):
        """
        Returns (afi, [(subject, filter)]). Remove all refine and except blocks
        as well as protocol and to specs.

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
            r = AFI_MATCH.match(mytext)
            ############# HACK HACK HACK !!! fix of a syntax error in RIPE DB in object
            ############# aut-num AS2852 (cesnet) that contains weird line with merged
            ############# afi spec and
            rh = AFI_MATCH_HACK.match(mytext)
            if rh:
                r = rh
            ############# END OF HACK

            if r:
                afi = r.group(1)
                mytext = r.group(2)
            else:
                afi = 'ANY'

        factors = self.decomposeExpression(mytext)

        return (direction, afi, [self.normalizeFactor(f, factors[1]) for f in factors[0]])

    def interpreter(self, mytext, rule, mp=False, ipv6=False):
        """
        Analyse and interpret the rule.

        subject = AS that is announcing the prefix to or as that the prefix is exported to by
        the AS that conains this rule
        prefix = prefix that is in question
        currentAsPath = aspath as it is (most likely) seen by the AS
        assetDirectory = HashObjectDir that conains the AsSetObjects
        fltrsetDirectory = HashObjectDir that conains the FilterSetObjects
        rtsetDirectory = HashObjectDir that conains the RouteSetObjects
        ipv6 = matching IPv6 route?
        """

        res = self.parseRule(mytext, rule, mp)  # return (direction, afi, [(subject, filter)])

        try:
            peer_as = self.peerings.returnPeering(res[2][0][0])
        except Exception:
            "TODO: Catch a custom exception"
            peer_as = rpsl.PeerAS(res[2][0][0])
            # logging.debug('New peering found (%s)' % res[2][0][0])
            pass

        # Check address family matches
        if res[1] != 'ANY' and res[1] != 'ANY.UNICAST':
            if ((ipv6 and res[1] != 'IPV6.UNICAST') or
                    ((not ipv6) and res[1] != 'IPV4.UNICAST')):
                return

        """
            Separation of roles. The peer class will get a pointer to the filter (hash value)
            while the real filter will be stored temporarily for the second round of resolving.
        """
        if res[2][0][1] != 'ANY':
            # Create a hash of the filter expression
            ha = str(xxhash.xxh64(res[2][0][1]).hexdigest())

            pf = rpsl.peerFilter(ha, res[2][0][1])
            self.fltrExpressions.appendFilter(pf)

            # Append in the peer a filter set(direction, afi, hash)
            try:
                peer_as.appendFilter((res[0], res[1], ha), mp)  # !!!!!!!!!!!!!
            except errors.UnsupportedAFIerror:
                logging.warning("Failed to append filter %s on peer %s" % (ha, peer_as.origin))

        pp = rpsl.PeeringPoint(res[1])
        if re.search('\sAT\s', mytext, re.I):
            """ === warning ===
                In case of peering on multiple network edges,
                more peering-IPs are present in the policy!!!
            """
            self.extractIPs(mytext, pp, mp)
            if peer_as.checkPeeringPointKey(pp.getKey()):
                pp = peer_as.returnPeeringPoint(pp.getKey())

        # check if optional action(s) exist
        if "ACTION" in mytext:
            if rule is "import":
                pal = rpsl.PolicyActionList(direction="import")
                self.extractActions(mytext, pal)
                pp.actions_in = pal
            else:
                pal = rpsl.PolicyActionList(direction="export")
                self.extractActions(mytext, pal, export=True)
                pp.actions_out = pal

        peer_as.appendPeeringPoint(pp)
        self.peerings.appentPeering(peer_as)


class ASNParser:
    def __init__(self, ASNObject, ipv6):
        self.ASNobj = ASNObject
        self.ipv4 = True
        self.ipv6 = ipv6

    def extractRoutes(self, db_object):

        # TODO, this function needs improvements
        if self.ipv4:
            for elem in db_object.iterfind('./objects/object[@type="route"]/primary-key'):
                new_prefix = None
                new_origin = None

                for subelem in elem.iterfind('./attribute[@name="route"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None or new_origin is not None:
                    self.ASNobj.routeObjDir.appendRouteObj(rpsl.RouteObject(new_prefix, new_origin))

        if self.ipv6:
            for elem in db_object.iterfind('./objects/object[@type="route6"]/primary-key'):
                new_prefix = None
                new_origin = None
                for subelem in elem.iterfind('./attribute[@name="route6"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None and new_origin is not None:
                    if new_prefix is not None or new_origin is not None:
                        self.ASNobj.routeObjDir.appendRouteObj(rpsl.Route6Object(new_prefix, new_origin))


class ASSetParser:
    def __init__(self, AsSetObject):
        self.setObj = AsSetObject

    def parseMembers(self, db_object, old_ASNDir, old_ASSetDir):

        new_ASSet = set()
        new_ASNset = set()

        for elem in db_object.iterfind('./objects/object[@type="as-set"]/attributes'):
            for subelem in elem.iterfind('./attribute[@name="members"]'):
                val = subelem.attrib.get("value")

                if rpsl.is_ASN(val):
                    self.setObj.ASNmembers.add(val)
                    try:
                        old_ASNDir.asnObjDir[val]
                    except KeyError:
                        new_ASNset.add(val)
                        pass

                elif rpsl.is_AS_set(val):
                    self.setObj.ASSetmember.add(val)
                    try:
                        old_ASSetDir.asSetObjDir[val]
                    except KeyError:
                        new_ASSet.add(val)

        old_ASSetDir.appendAsSetObj(self.setObj)
        return new_ASSet, new_ASNset


class RSSetParser:
    def __init__(self, RouteSetObject, ipv6):
        self.setObj = RouteSetObject
        self.ipv4_enabled = True
        self.ipv6_enabled = ipv6

    def parseMembers(self, db_object, old_RSSetDir):

        new_RSSet = set()
        # TODO, this function needs improvements
        if self.ipv4_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route-set"]/attributes'):
                for subelem in elem.iterfind('./attribute[@name="members"]'):
                    new_member = subelem.attrib.get("value").strip()

                    if rpsl.is_rs_set(new_member):
                        self.setObj.RSSetsDir.add(new_member)
                        try:
                            old_RSSetDir.RouteSetObjDir[new_member]
                        except KeyError:
                            new_RSSet.add(new_member)
                            pass

                    else:
                        ro = rpsl.RouteObject(new_member, self.setObj.route_set)
                        self.setObj.members.appendRouteObj(ro)

        if self.ipv6_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route-set"]/attributes'):
                for subelem in elem.iterfind('./attribute[@name="mp-members"]'):
                    new_member = subelem.attrib.get("value").strip()

                    if rpsl.is_rs_set(new_member):
                        self.setObj.RSSetsDir.add(new_member)
                        try:
                            old_RSSetDir.RouteSetObjDir[new_member]
                        except KeyError:
                            new_RSSet.add(new_member)
                            pass

                    else:
                        ro = rpsl.Route6Object(new_member, "None")
                        self.setObj.mp_members.appendRouteObj(ro)

        old_RSSetDir.appendRouteSetObj(self.setObj)
        return new_RSSet
