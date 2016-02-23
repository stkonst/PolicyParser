__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com)'
import xml.etree.ElementTree as et
import re
import xxhash

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
PARSE_RANGE = re.compile('^\^([0-9]+)-([0-9]+)$')
################# HACK HACK HACK
AFI_MATCH_HACK = re.compile('^AFI\s+(IPV6.UNICAST)(FROM.*)$')
################# END OF HACK

IMPORT_FACTOR_MATCH = re.compile('^FROM\s+([^\s]+)(\s+(.*)?\s?ACCEPT(.+))?$')
EXPORT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?ANNOUNCE(.+))?$')
DEFAULT_FACTOR_MATCH = re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?NETWORKS(.+)|.*)?$')

''' End of Tomas' expressions for parsers '''

ACTION_RESHAPE = re.compile(r'\s|[{\s*|\s*}]')


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
        except:
            raise Exception('Failed to load DB content in XML format')

    def readPolicy(self):

        tools.d('Will parse policy for %s' % self.autnum)
        for elem in self.etContent.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):

            line_parsed = False
            if self.ipv4_enabled:

                if "import" == elem.attrib.get("name"):
                    try:
                        self.analyser(elem.attrib.get("value").upper(), mp=False, rule="import")
                        line_parsed = True
                    except:
                        tools.w("Failed to parse import {%s}" % elem.attrib.get("value"))
                        pass

                elif "export" == elem.attrib.get("name"):
                    try:
                        self.analyser(elem.attrib.get("value").upper(), mp=False, rule="export")
                        line_parsed = True
                    except:
                        tools.w("Failed to parse export {%s}" % elem.attrib.get("value"))
                        pass

            if not line_parsed and self.ipv6_enabled:

                if "mp-import" == elem.attrib.get("name"):
                    try:
                        self.analyser(elem.attrib.get("value").upper(), mp=True, rule="import")
                    except:
                        tools.w("Failed to parse import {%s}" % elem.attrib.get("value"))
                        pass

                elif "mp-export" == elem.attrib.get("name"):
                    try:
                        self.analyser(elem.attrib.get("value").upper(), mp=True, rule="export")
                    except:
                        tools.w("Failed to parse export {%s}" % elem.attrib.get("value"))
                        pass

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

    def extractActions(self, line, PolicyActionList, export=False):

        if export:
            actions = re.search(r'ACTION(.*)ANNOUNCE', line, re.I).group(1).split(";")
        else:
            actions = re.search(r'ACTION(.*)ACCEPT', line, re.I).group(1).split(";")

        for i, a in enumerate(actions):
            reshaped = re.sub(ACTION_RESHAPE, '', a)
            if '.=' in reshaped:
                # I know it's a HACK. But I will blame RPSL 4 that
                items = reshaped.split('.=')
                PolicyActionList.appendAction(rpsl.PolicyAction(i, items[0], ".=", items[1]))
            elif '=' in reshaped:
                items = reshaped.split('=')
                PolicyActionList.appendAction(rpsl.PolicyAction(i, items[0], "=", items[1]))

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

        # defaultRule = ('AutNumDefaultRule')
        # factors = _decomposeExpression(text, defaultRule)
        factors = self.decomposeExpression(mytext)

        return (direction, afi, [self.normalizeFactor(f, factors[1]) for f in factors[0]])

    def analyser(self, mytext, rule, mp=False, ipv6=False):
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

        returns:
        0 when analyser is OK
        1 when AFI does not analyser
        2 when subject can not be expanded (= not ASN nor AS-SET)
        3 when not analyser for the subject has been found in factors
        >=4 and filter analyser failed (see AutNumRule.matchFilter for details)
        """

        res = self.parseRule(mytext, rule, mp)  # return (direction, afi, [(subject, filter)])
        # tools.w(str(res))

        try:
            peer_as = self.peerings.returnPeering(res[2][0][0])
        except Exception:
            peer_as = rpsl.PeerAS(res[2][0][0])
            # tools.d('New peering found (%s)' % res[2][0][0])
            pass

        # Check address family matches
        if res[1] != 'ANY' and res[1] != 'ANY.UNICAST':
            if ((ipv6 and res[1] != 'IPV6.UNICAST') or
                    ((not ipv6) and res[1] != 'IPV4.UNICAST')):
                return 1

        """
            Separation of roles. The peer class will get a pointer to the filter (hash value)
            while the real filter will be stored temporarily for the second round of resolving.
        """
        # Create a hash of the filter expression
        ha = str(xxhash.xxh64(res[2][0][1]).hexdigest())

        pf = rpsl.peerFilter(ha, res[1], res[2][0][1])
        self.fltrExpressions.appendFilter(pf)

        # Append in the peer a filter set(direction, afi, hash)
        try:
            peer_as.appendFilter((res[0], res[1], ha), mp)
        except:
            tools.w("Failed to append filter %s on peer %s" % (ha, peer_as.origin))

        pp = rpsl.PeeringPoint(mp)
        if re.search('\sAT\s', mytext, re.I):
            """ === WARNING ===
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
                    if val not in old_ASNDir.asnObjDir.keys():
                        new_ASNset.add(val)

                elif rpsl.is_AS_set(val):
                    if val not in old_ASSetDir.asSetObjDir.keys():
                        new_ASSet.add(val)
                        self.setObj.ASSetmember.add(val)

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
                new_member = None
                for subelem in elem.iterfind('./attribute[@name="members"]'):
                    new_member = subelem.attrib.get("value").strip()

                    if rpsl.is_rs_set(new_member):
                        if new_member not in old_RSSetDir.RouteSetObjDir.keys():
                            new_RSSet.add(new_member)

                    else:
                        ro = rpsl.RouteObject(new_member, self.setObj.route_set)
                        self.setObj.members.appendRouteObj(ro)

        if self.ipv6_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route-set"]/attributes'):
                new_member = None
                for subelem in elem.iterfind('./attribute[@name="mp-members"]'):
                    new_member = subelem.attrib.get("value").strip()

                    if rpsl.is_rs_set(new_member):
                        if new_member not in old_RSSetDir.RouteSetObjDir.keys():
                            new_RSSet.add(new_member)

                    else:
                        ro = rpsl.Route6Object(new_member, "None")
                        self.setObj.members.appendRouteObj(ro)

        old_RSSetDir.appendRouteSetObj(self.setObj)
        return new_RSSet

