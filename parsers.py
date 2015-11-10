__author__ = 'stavros'
import xml.etree.ElementTree as et
import re

import libtools as tools
import rpsl

''' Start of Tomas' expressions for parsers '''
FACTOR_SPLIT_ACCEPT = 'ACCEPT'  # regexp would be better but slower
FACTOR_SPLIT_ANNOUNCE = 'ANNOUNCE'  # regexp would be better but slower
FACTOR_SPLIT_NETWORKS = 'NETWORKS'  # regexp would be better but slower
FACTOR_CONST_ACCEPT = 'ACCEPT'
FACTOR_CONST_ANNOUNCE = 'ANNOUNCE'
FACTOR_CONST_NETWORKS = 'NETWORKS'
FACTOR_SPLIT_FROM = re.compile('^(|.*\s+)FROM\s+')
FACTOR_SPLIT_TO = re.compile('^(|.*\s+)TO\s+')
AFI_MATCH = re.compile('^AFI\s+([^\s]+)\s+(.*)$')
################# HACK HACK HACK
AFI_MATCH_HACK = re.compile('^AFI\s+(IPV6.UNICAST)(FROM.*)$')
################# END OF HACK

IMPORT_FACTOR_MATCH = re.compile('^FROM\s+([^\s]+)(\s+(.*)?\s?ACCEPT(.+))?$')
EXPORT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?ANNOUNCE(.+))?$')
DEFAULT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?NETWORKS(.+)|.*)?$')

ASN_MATCH = re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH = re.compile('^\{([^}]*)\}(\^[0-9\+-]+)?$')
PFX_FLTR_PARSE = re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9\+-]+)?$')
REGEXP_FLTR_PARSE = re.compile('^<([^>]+)>$')
''' End of Tomas' expressions for parsers '''

ACTION_RESHAPE = re.compile(r'\s|[{\s*|\s*}]')


class PolicyParser:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.etContent = et.ElementTree()
        self.autnum = autnum
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6
        self.peerings = rpsl.PeerObjDir()

    def assignContent(self, xmltext):
        try:
            self.etContent = et.fromstring(xmltext)
        except:
            raise Exception('Failed to load DB content in XML format')

    def readPolicy(self):

        tools.d('Will parse policy for %s' % self.autnum)
        for elem in self.etContent.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):

            line_parsed = False
            if self.ipv4_enabled:

                if "import" == elem.attrib.get("name"):
                    self.parseImport(elem.attrib.get("value").upper())
                    line_parsed = True

                elif "export" == elem.attrib.get("name"):
                    self.parseExport(elem.attrib.get("value").upper())
                    line_parsed = True

            if not line_parsed and self.ipv6_enabled:

                if "mp-import" == elem.attrib.get("name"):
                    self.parseImport(elem.attrib.get("value").upper(), mp=True)

                elif "mp-export" == elem.attrib.get("name"):
                    self.parseExport(elem.attrib.get("value").upper(), mp=True)

    def extractIPs(self, policy_object, PeeringPoint, mp=False):

        remoteIP = re.split('\sAT\s', policy_object, re.I)[0].split()[-1]
        localIP = re.split('\sACTION\s', policy_object, re.I)[0].split()[-1]

        if mp:
            """ RPSL Allows also 1 out of the 2 IPs to exist. """
            # TODO make it less strict and more flexible
            if tools.is_valid_ipv6(remoteIP) and tools.is_valid_ipv6(localIP):
                PeeringPoint.appendAddresses(localIP, remoteIP)
        elif tools.is_valid_ipv4(remoteIP) and tools.is_valid_ipv4(localIP):
            PeeringPoint.appendAddresses(localIP, remoteIP)

    def extractActions(self, line, PolicyActionList, mp=False):
        actions = re.search(r'ACTION(.*)ACCEPT', line, re.I).group(1).split(";")

        for i, a in enumerate(actions):
            reshaped = re.sub(ACTION_RESHAPE, '', a)
            if '.=' in reshaped:
                # I know it's a HACK. But I will blame RPSL 4 that
                items = reshaped.split('.=')
                PolicyActionList.appendAction(rpsl.PolicyAction(i, items[0], ".=", items[1]))
            elif "=" in reshaped:
                items = reshaped.split('=')
                PolicyActionList.appendAction(rpsl.PolicyAction(i, items[0], "=", items[1]))

    def parseImport(self, line, mp=False):

        if mp:
            peer_asnum = re.search('(AS\d*\s)', re.split('FROM', line, re.I)[1].strip(), re.I).group(1).strip()
        else:
            peer_asnum = re.split('\s', line)[1].strip()

        try:
            peer_as = self.peerings.returnPeering(peer_asnum)
        except:
            peer_as = rpsl.PeerAS(peer_asnum)
            tools.d('New peering found (%s)' % peer_asnum)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*ACCEPT\.*', line, re.I)[1].split()
        peer_as.appendImportFilters(filter_items)

        pp = rpsl.PeeringPoint(mp)
        if re.search('\sAT\s', line, re.I):
            """ WARNING: In case of peering on multiple network edges, more peering-IPs are present in the policy!!! """
            self.extractIPs(line, pp, mp)

        # Before third step check if optional action(s) exist
        if "ACTION" in line:
            acList = rpsl.PolicyActionList("import")
            self.extractActions(line, acList, mp)
            pp.actions_in = acList

        peer_as.appendPeeringPoint(pp)
        self.peerings.appentPeering(peer_as)

    def parseExport(self, line, mp=False):

        if mp:
            peer_asnum = re.search('(AS\d*\s)', re.split('TO', line, re.I)[1].strip(), re.I).group(1).strip()
        else:
            peer_asnum = re.split('\s', line)[1].strip()

        try:
            peer_as = self.peerings.returnPeering(peer_asnum)
        except:
            peer_as = rpsl.PeerAS(peer_asnum)
            tools.d('New peering found (%s)' % peer_asnum)

        # First get the announce (filter) items
        filter_items = re.split('\.*ANNOUNCE\.*', line, re.I)[1].split()
        peer_as.appendExportFilters(filter_items)

        pp = rpsl.PeeringPoint(mp)
        if re.search('\sAT\s', line, re.I):
            """ WARNING: In case of peering on multiple network edges, more peering-IPs are present in the policy!!! """
            self.extractIPs(line, pp, mp)
            if peer_as.checkPeeringPointKey(pp.getKey()):
                pp = peer_as.returnPeeringPoint(pp.getKey())

        # Then let's receive the actions_out that need to be applied
        if "ACTION" in line:
            #  TODO enumerate actions_in to get their order and append them in an ActionList
            acList = rpsl.PolicyActionList("export")
            self.extractActions(line, acList, mp)
            pp.actions_out = acList

        self.peerings.appentPeering(peer_as)

    def extractRoutesFromSearch(self, db_object, RouteObjectDir):

        # TODO, this function needs improvements
        if self.ipv4_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route"]/primary-key'):
                new_prefix = None
                new_origin = None
                for subelem in elem.iterfind('./attribute[@name="route"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None or new_origin is not None:
                    RouteObjectDir.appendRouteObj(rpsl.RouteObject(new_prefix, new_origin))

        if self.ipv6_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route6"]/primary-key'):
                new_prefix = None
                new_origin = None
                for subelem in elem.iterfind('./attribute[@name="route6"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None and new_origin is not None:
                    if new_prefix is not None or new_origin is not None:
                        RouteObjectDir.appendRouteObj(rpsl.Route6Object(new_prefix, new_origin))


# Aut-num object machinery
# Thanks to Tomas

class AutNumRuleParser(object):
    """ Abstract base for internal representation of a rule in an aut-num object.
        Thanks to Tomas
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """

        self.mp = mp
        self.text = line.upper()

    def __str__(self):
        return "%s%s : %s" % (self.__class__.__name__, (' MP' if self.mp else ''), self.text)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def _decomposeExpression(text, defaultRule=False):
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
                tools.w("Syntax error: Can not find selectors in:", e, "decomposing expression:", text)
                # raise Exception("Can not find selectors in: "+e)

        # here regexps are necessary
        if len(FACTOR_SPLIT_FROM.split(sel)) > 2:
            return ([str('FROM ' + f.strip()) for f in FACTOR_SPLIT_FROM.split(sel)[2:]], fltr)

        elif len(FACTOR_SPLIT_TO.split(sel)) > 2:
            return ([str('TO ' + f.strip()) for f in FACTOR_SPLIT_TO.split(sel)[2:]], fltr)

        else:
            raise Exception("Can not find filter factors in: '" + sel + "' in text: " + text)

    @staticmethod
    def _normalizeFactor(selector, fltr):
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

    def _parseRule(self):
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
        text = self.text
        if self.mp:
            r = AFI_MATCH.match(self.text)
            ############# HACK HACK HACK !!! fix of a syntax error in RIPE DB in object
            ############# aut-num AS2852 (cesnet) that contains weird line with merged
            ############# afi spec and
            rh = AFI_MATCH_HACK.match(self.text)
            if rh:
                r = rh
            ############# END OF HACK

            if r:
                afi = r.group(1)
                text = r.group(2)
            else:
                afi = 'ANY'

        defaultRule = (self.__class__.__name__ == 'AutNumDefaultRule')
        factors = AutNumRuleParser._decomposeExpression(text, defaultRule)

        return (afi, [AutNumRuleParser._normalizeFactor(f, factors[1]) for f in factors[0]])

    @staticmethod
    def isASN(asn):
        return ASN_MATCH.match(str(asn).strip()) != None

    @staticmethod
    def isPfxFilter(fltr):
        return PFX_FLTR_MATCH.match(fltr) != None

    @staticmethod
    def isPfx(pfx):
        return PFX_FLTR_PARSE.match(pfx) != None

    @staticmethod
    def matchPfxFltr(fltr, prefix, ipv6):
        # tools.d("matchPfxFltr:", fltr, prefix)

        def _parseRange(rng, lowbound, ipv6):
            PARSE_RANGE = re.compile('^\^([0-9]+)-([0-9]+)$')
            maxpl = 128 if ipv6 else 32
            rng = rng.strip()

            if rng == '^+':
                return [int(lowbound), maxpl]
            elif rng == '^-':
                return [int(lowbound) + 1, maxpl]

            elif rng[1:].isdigit():
                return [int(rng[1:]), int(rng[1:])]

            elif PARSE_RANGE.match(rng):
                m = PARSE_RANGE.match(rng)
                return [int(m.group(1)), int(m.group(2))]

            else:
                tools.w("Can not parse range:", rng)
                return [0, maxpl]

        if fltr.strip() == '{}':
            return False

        m = PFX_FLTR_MATCH.match(fltr.strip())
        grng = None
        if m.group(2):
            grng = _parseRange(m.group(2), ipv6)

        for f in m.group(1).strip().split(','):
            f = f.strip()
            m = PFX_FLTR_PARSE.match(f)
            fnet = None
            rng = None
            if m:
                fnet = ipaddr.IPNetwork(m.group(1))
                if m.group(2):
                    rng = _parseRange(m.group(2), fnet.prefixlen, ipv6)
            else:
                raise Exception("Can not parse filter: " + fltr + " matching with pfx " + prefix)

            pnet = ipaddr.IPNetwork(prefix)

            # take into account possibility of multiple ranges,
            # i.e. {1.2.0.0/16^+}^24-32 (use the most specific one, left-most)
            # if no range is set, take the prefix as it is
            if not rng and grng:
                rng = grng
            if not rng:
                rng = [fnet.prefixlen, fnet.prefixlen]

            # finaly do the check
            if (pnet in fnet) and (rng[0] <= pnet.prefixlen) and (rng[1] >= pnet.prefixlen):
                return True

        # no match means filter failed -> false
        return False

    @staticmethod
    def isAsPathRegExp(fltr):
        return REGEXP_FLTR_PARSE.match(fltr) != None

    @staticmethod
    def matchAsPathRegExp(fltr, asPath):
        """
        Apply regexp from regexp filter. This is a bit bold because
        we just use Python's re.

        Allocated failure code is 13 and dunno code 21. OK=0.
        """

        if len(asPath) == 0:
            return 13

        ref = REGEXP_FLTR_PARSE.match(fltr).group(1)  # should not fail... test it before
        ref.replace('PEERAS', asPath[0])

        if not ref.startswith('^'):
            ref = '.*' + ref
        if not ref.endswith('$'):
            ref += '.*'

        if ref.find('AS-') > -1:
            # can not recursively expand as-set names, return dunno
            # this is potential problem of large scale, but it is more
            # efficient to adress this by manual analysis or by own script
            # because regexp parsing is anyway problematic when RPSL is
            # being translated to Cisco/Juniper/... configs
            tools.w("matchAsPathRegExp shortcut. fltr:", fltr, "aspath", asPath)
            return 21

        # Attempt the match
        asps = ''
        for i, asn in enumerate(asPath):
            asps += (asn + ' ')
        asps = asps.strip()

        try:
            if re.match(ref, asps):
                return 0
        except:
            tools.w("matchAsPathRegExp failed due to invalid regexp. fltr:", fltr, "aspath", asPath)
            return 21

        # return not-match otherwise
        return 13

    @staticmethod
    def matchFilter(fltr, prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6=False,
                    recursion_list=None):
        """ Matches filter fltr to prefix with currentAsPath.
        Using assetDirectory, fltrsetDirectory and rtsetDirectory.

        Returns:
        0 when filter matches (=OK)
        1-3 are reserved for calling functions
        4 when fltr ASN != origin
        5 when as-set recursive match fails
        6 when unknown as-set is in the filter
        7 PeerAS match failed
        8 { prefix^range } match failed
        9 composed expression failed
        10 unknown fltr-set
        11 unkown route-set or route-set not match
        13 regexp failed to validate
        14 empty filter (None or '')
        20 unknown filter (=dunno)
        21 unknown regexp (=dunno)
        22 community can not be decided (=dunno)
        """

        # tools.d("Matching filter", fltr, 'prefix', prefix, 'currentAsPath', str(currentAsPath))

        origin = (currentAsPath[-1].strip() if currentAsPath else '')
        if not fltr:
            return 14  # empty filter -> fail
        fltr = fltr.strip().rstrip(';').strip()


        # Recrusion for composed filters (with NOT, AND and OR)
        def findOper(text, oper):
            """ Find the first occurance of operator that is out of the parentheses. """
            pc = 0
            for i, c in enumerate(text):
                if c == '(':
                    pc += 1
                if c == ')':
                    pc -= 1
                if pc == 0 and text[i:].startswith(oper):
                    return i
            return -1

        op = " OR "
        i = findOper(fltr, op)
        if i >= 0:
            # tools.d("OR recursion a:", fltr[:i], "b:", fltr[i+len(op):])
            a = AutNumRuleParser.matchFilter(fltr[:i], prefix, currentAsPath, assetDirectory, fltrsetDirectory,
                                             rtsetDirectory, ipv6)
            b = AutNumRuleParser.matchFilter(fltr[i + len(op):], prefix, currentAsPath, assetDirectory,
                                             fltrsetDirectory,
                                             rtsetDirectory, ipv6)
            # tools.d("Recusion result a:", a, "b", b)
            if a >= 20 and b >= 20:
                return 20

            return (0 if a == 0 or b == 0 else 9)

        op = " AND "
        i = findOper(fltr, op)
        if i >= 0:
            # tools.d("AND recursion a:", fltr[:i], "b:", fltr[i+len(op):])
            a = AutNumRuleParser.matchFilter(fltr[:i], prefix, currentAsPath, assetDirectory, fltrsetDirectory,
                                             rtsetDirectory, ipv6)
            b = AutNumRuleParser.matchFilter(fltr[i + len(op):], prefix, currentAsPath, assetDirectory,
                                             fltrsetDirectory,
                                             rtsetDirectory, ipv6)
            # tools.d("AND recusion result a:", a, "b", b)
            if a >= 20 or b >= 20:
                return 20
            return (0 if a == 0 and b == 0 else 9)

        op = "NOT "
        i = findOper(fltr, op)
        if i >= 0:
            # tools.d("NOT recursion a:", fltr[:i])
            a = AutNumRuleParser.matchFilter(fltr[i + len(op):], prefix, currentAsPath, assetDirectory,
                                             fltrsetDirectory,
                                             rtsetDirectory, ipv6)
            # tools.d("NOT recusion result a:", a)
            if a >= 20:
                return 20
            return (0 if not a == 0 else 9)

        # Parentheses
        if fltr[0] == '(':
            if fltr[-1] == ')':
                return AutNumRuleParser.matchFilter(fltr[1:-1], prefix, currentAsPath, assetDirectory, fltrsetDirectory,
                                                    rtsetDirectory, ipv6)
            else:
                raise Exception("Can not parse parentheses in filter:", fltr)

        # Atomic statements

        if fltr.strip() == 'ANY':
            return 0

        elif fltr.strip() == 'PEERAS':
            if origin == currentAsPath[0]:  # allow as-path prepending, i.e. aspath can be [x,x,x,x] and origin x
                return 0
            else:
                return 7

        # ASN (= i.e. AS1)
        elif AutNumRuleParser.isASN(fltr):
            if fltr == origin:
                # tools.d("True, fltr ASN == origin", origin)
                return 0
            else:
                # tools.d("False, fltr ASN != origin f:", fltr, 'o:', origin)
                return 4

        # as-set
        elif AsSetObject.isAsSet(fltr):
            if fltr in assetDirectory.table:
                # special recursion is used for speedup (otherwise
                # recursion in this method could do the job)
                if assetDirectory.table[fltr].recursiveMatch(origin, assetDirectory):
                    # tools.d('True, as-set recursive match f:', fltr, 'o:', origin)
                    return 0
                else:
                    # tools.d('False, no as-set recursive match f:', fltr, 'o:', origin)
                    return 5
            else:
                # tools.d('False, as-set not known. f:', fltr, 'o:', origin)
                return 6

        # prefix filter (= i.e. { 1.2.3.0/16^23-24 })
        elif AutNumRuleParser.isPfxFilter(fltr):
            if AutNumRuleParser.matchPfxFltr(fltr, prefix, ipv6):
                return 0
            else:
                return 8

        # filter-set
        elif FilterSetObject.isFltrSet(fltr):
            if fltr in fltrsetDirectory.table:
                if ipv6:
                    return AutNumRuleParser.matchFilter(fltrsetDirectory.table[fltr].mp_filter, prefix, currentAsPath,
                                                        assetDirectory,
                                                        fltrsetDirectory, rtsetDirectory, ipv6)
                else:
                    return AutNumRuleParser.matchFilter(fltrsetDirectory.table[fltr].filter, prefix, currentAsPath,
                                                        assetDirectory,
                                                        fltrsetDirectory, rtsetDirectory, ipv6)
            else:
                return 10

        # route-set
        elif RouteSetObject.isRouteSet(fltr):
            if fltr in rtsetDirectory.table:
                rts = rtsetDirectory.table[fltr]

                # prevent infinite recursion
                rcl = (recursion_list if recursion_list else [])
                if rts.getKey() in rcl:
                    return 11
                rcl.append(rts.getKey())

                # recursively resolve members
                # this needs own recursion because contents might be
                # another route-set, as-set and/or IP range
                members = (rts.mp_members if ipv6 else rts.members)
                for m in members:
                    if AutNumRuleParser.isPfx(m):  # prefix or prefix range
                        if AutNumRuleParser.matchFilter('{ ' + m + ' }', prefix, currentAsPath, assetDirectory,
                                                        fltrsetDirectory, rtsetDirectory, ipv6) == 0:
                            return 0
                    else:  # recursion (might contain another route-set, as-set or ASN)
                        if AutNumRuleParser.matchFilter(m, prefix, currentAsPath, assetDirectory,
                                                        fltrsetDirectory, rtsetDirectory, ipv6, rcl) == 0:
                            return 0
            return 11

        # <regular expression>
        elif AutNumRuleParser.isAsPathRegExp(fltr):
            r = AutNumRuleParser.matchAsPathRegExp(fltr, currentAsPath)
            if r > 20:
                return 20
            else:
                return r

        # can not decide communities -> DUNNO
        elif fltr.find('COMMUNITY(') > -1 or fltr.find('COMMUNITY.CONTAINS(') > -1:
            return 22

        # list of identifiers (= from AS666 accept AS1 AS2 AS-HELL)
        elif len(fltr.split()) > 1:
            for g in fltr.split():
                if AutNumRuleParser.matchFilter(g, prefix, currentAsPath, assetDirectory,
                                                fltrsetDirectory, rtsetDirectory, ipv6) == 0:
                    return 0
            return 4  # most tools use case is listing ASNs, therefore inherit ASN failure code

        # Dunno, return False
        tools.w("Can not parse filter:", fltr, 'hint pfx:', prefix, 'aspath:', currentAsPath)
        # TODO rm
        global filterdebug
        tools.w("Filter debug:", filterdebug)
        return 20

    def match(self, subject, prefix, currentAsPath, assetDirectory, fltrsetDirectory,
              rtsetDirectory, prngsetDirectory, ipv6=False):
        """
        Interpret the rule and decide whether a prefix should be accepted or not.

        subject = AS that is announcing the prefix to or as that the prefix is exported to by
        the AS that conains this rule
        prefix = prefix that is in question
        currentAsPath = aspath as it is (most likely) seen by the AS
        assetDirectory = HashObjectDir that conains the AsSetObjects
        fltrsetDirectory = HashObjectDir that conains the FilterSetObjects
        rtsetDirectory = HashObjectDir that conains the RouteSetObjects
        ipv6 = matching IPv6 route?

        returns:
        0 when match is OK
        1 when AFI does not match
        2 when subject can not be expanded (= not ASN nor AS-SET)
        3 when not match for the subject has been found in factors
        >=4 and filter match failed (see AutNumRule.matchFilter for details)
        """

        # Fast-path, fail for IPv6 with non-MP rule
        # This is problematic... A lot of people does not have proper
        # routing politics written with mp-* rules and people
        # just freely intepret the aut-num objects as being multi-protocol
        # by default. (Which is not true...)
        if (not self.mp) and ipv6:
            return False

        res = self._parseRule()  # return (afi, [(subject, filter)])

        # Check address family matches
        if res[0] != 'ANY' and res[0] != 'ANY.UNICAST':
            if ((ipv6 and res[0] != 'IPV6.UNICAST') or
                    ((not ipv6) and res[0] != 'IPV4.UNICAST')):
                return 1

        # TODO rm
        global filterdebug

        # Walk through factors and find whether there is subject match,
        # run the filter if so
        for f in res[1]:
            # tools.d("Match? sub=", subject, 'f=', str(f))

            if self.isASN(f[0]):
                if f[0] == subject:
                    # TODO rm
                    filterdebug = f
                    return AutNumRuleParser.matchFilter(f[1], prefix, currentAsPath, assetDirectory,
                                                        fltrsetDirectory, rtsetDirectory, ipv6)

            elif AsSetObject.isAsSet(f[0]):
                # TODO rm
                filterdebug = f
                if f[0] in assetDirectory.table:
                    if assetDirectory.table[f[0]].recursiveMatch(subject, assetDirectory):
                        return AutNumRuleParser.matchFilter(f[1], prefix, currentAsPath, assetDirectory,
                                                            fltrsetDirectory, rtsetDirectory, ipv6)

            elif PeeringSetObject.isPeeringSet(f[0]):
                # TODO rm
                filterdebug = f
                if f[0] in prngsetDirectory.table:
                    if prngsetDirectory.table[f[0]].recursiveMatch(subject, prngsetDirectory):
                        return AutNumRuleParser.matchFilter(f[1], prefix, currentAsPath, assetDirectory,
                                                            fltrsetDirectory, rtsetDirectory, ipv6)

            else:
                # raise Exception("Can not expand subject: "+str(f[0]))
                tools.w("Can not expand subject:", str(f[0]), 'in rule', self.text)
                return 2

        # No match of factor for the subject means that the prefix should not appear
        return 3


class AutNumImportRule(AutNumRuleParser):
    """ Internal representation of a rule (=import, mp-import line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRuleParser.__init__(self, line, mp)


class AutNumDefaultRule(AutNumRuleParser):
    """ Internal representation of a default rule (=default, mp-default line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRuleParser.__init__(self, line, mp)


class AutNumExportRule(AutNumRuleParser):
    """ Internal representation of a rule (=export, or mp-export line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRuleParser.__init__(self, line, mp)


        ############################################
