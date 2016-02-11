__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl) '
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com) '
import re

ASN_MATCH = re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH = re.compile('^\{([^}]*)\}(\^[0-9\+-]+)?$')
PFX_FLTR_PARSE = re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9\+-]+)?$')
REGEXP_FLTR_PARSE = re.compile('^<([^>]+)>$')
AS_SET_MATCH = re.compile('^(AS\d+:)*AS-(\w|-)*$', re.I)
RS_SET_MATCH = re.compile('^RS-(\w|-)*$', re.I)
RTR_SET_MATCH = re.compile('^RTR-(\w|-)*$', re.I)
FLTR_SET_MATCH = re.compile('^FLTR-(\w|-)*$', re.I)


def is_ASN(asn):
    return ASN_MATCH.match(str(asn).strip()) != None


def is_pfx_filter(fltr):
    return PFX_FLTR_MATCH.match(fltr) != None


def is_pfx(pfx):
    return PFX_FLTR_PARSE.match(pfx) != None


def is_AS_set(as_set):
    return AS_SET_MATCH.match(as_set) != None


def is_rtr_set(rtr_set):
    return RTR_SET_MATCH.match(rtr_set) != None


def is_rs_set(rs_set):
    return RS_SET_MATCH.match(rs_set) != None


def is_fltr_set(fltr_set):
    return FLTR_SET_MATCH.match(fltr_set) != None


class RpslObject(object):
    """ Thanks to Tomas """

    def __repr__(self):
        return self.__str__()

    def getKey(self):
        """
        Returns key value that should correspond to the object key in RPSL standard view.
        It is here for common HashObjectDirectory to use it for constructing lookup table.
        """
        raise Exception("This is abstract object. Dunno what my key is!")


# Route object machinery

class RouteObject(RpslObject):
    """
    Internal representation of route RPSL object.
    Thanks to Tomas
    """

    ROUTE_ATTR = 'ROUTE'
    ORIGIN_ATTR = 'ORIGIN'
    MEMBEROF_ATTR = 'MEMBER-OF'

    def __init__(self, route, origin):
        self.route = route
        self.origin = origin
        self.memberof = []

    def getKey(self):
        return self.route

    def __str__(self):
        return 'RouteObject: ' + str(self.route) + '->' + str(self.origin)


class Route6Object(RouteObject):
    """
    Internal representation of route6 RPSL object.
    Thanks to Tomas
    """

    # inherit route object and change only the key attribute indicator
    ROUTE_ATTR = 'ROUTE6'


class RouteObjectDir(object):
    """
    A Class for storing Route objects in a dictionary.
    Thanks to Tomas.
    """
    # TODO extend with a RouteTree to store routes in a tree based structure and provide functions for fast lookup
    def __init__(self, ipv6=True):
        self.originTable = {}
        self.ipv6 = ipv6
        if self.ipv6:
            self.originTableV6 = {}

    def appendRouteObj(self, RouteObject):
        if RouteObject.ROUTE_ATTR == 'ROUTE6':
            self.originTableV6[RouteObject.getKey] = RouteObject
        elif RouteObject.ROUTE_ATTR == 'ROUTE':
            self.originTable[RouteObject.getKey] = RouteObject
        else:
            raise Exception('Failed to insert Route object to dictionary')

    def enumerateObjs(self):
        for k in self.originTable.keys():
            for o in self.originTable[k]:
                yield o

    def enumerateObjsV6(self):
        for k in self.originTableV6.keys():
            for o in self.originTableV6[k]:
                yield o


class PolicyAction:
    # TODO Create a more detailed Action Machinery (see spliter)
    def __init__(self, i, attr, oper, val):
        self.order = i
        self.rp_attr = attr
        self.rp_operator = oper
        self.rp_value = val

    def __str__(self):
        return '%s%s%s' % (self.rp_attr, self.rp_operator, self.rp_value)


class PolicyActionList:
    def __init__(self, direction):
        self.actionDir = dict()
        self.direction = direction

    def appendAction(self, PolicyAction):
        self.actionDir[PolicyAction.order] = PolicyAction


# Set-* objects

class AsSetObject(RpslObject):
    """ Internal representation of as-set RPSL object. """

    ASSET_ATTR = 'AS-SET'
    MEMBERS_ATTR = 'MEMBERS'

    @staticmethod
    def _parseMembers(members):
        for m in members.strip().split(','):
            yield m.strip().upper()

    @staticmethod
    def isAsSet(name):
        """
        Returns True when the name appears to be as-set name (=key)
        according to RPSL specs. """
        return str(name).upper().find('AS-') > -1

    def __init__(self, name):
        RpslObject.__init__(self)
        self.as_set = name
        self.members = []

        # for (a, v) in RpslObject.splitLines(self.text):
        #     if a == self.ASSET_ATTR:
        #         self.as_set = v.strip().upper()
        #
        #     elif a == self.MEMBERS_ATTR:
        #         # flatten the list in case we have this:
        #         # members: AS123, AS456, AS-SOMETHING
        #         # members: AS234, AS-SMTHNG
        #         for m in AsSetObject._parseMembers(v):
        #             self.members.append(m)
        #
        #     else:
        #         pass  # ignore unrecognized lines
        #
        # if not self.as_set:
        #     raise Exception("Can not create AsSetObject out of text: " + str(textlines))

    def getKey(self):
        return self.as_set

    # def recursiveMatch(self, target, hashObjDir, recursionList=None):
    #     """
    #     This methods does recursion in the objects members and tries to find analyser
    #     with the target identifier.
    #
    #     This is being used by filter matching instead of full filter recursion because we
    #     know that this type of object could hold only ASNs or references to another
    #     as-sets and therefore full filter recursion is not needed and this special
    #     recursion offers mild speedup.
    #     """
    #
    #     if recursionList == None:
    #         recursionList = []
    #
    #     # common.d("AsSetObject recursiveMatch: target", target, 'in', self.getKey(), 'recursionList', recursionList)
    #     #        common.d("Members:", self.members)
    #     # prevent recusion loop
    #     if self.getKey() in recursionList:
    #         return False
    #     recursionList.append(self.getKey())
    #
    #     if target in self.members:
    #         return True
    #
    #     for m in self.members:
    #         if self.isAsSet(m) and m in hashObjDir.table:
    #             r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
    #             if r:
    #                 return True
    #
    #     return False

    def __str__(self):
        return 'AsSetObject: %s -< %s' % (self.as_set, str(self.members))


class PeeringSetObject(RpslObject):
    """ Internal representation of prng-set RPSL object. """

    PEERINGSET_ATTR = 'PEERING-SET'
    PEERING_ATTR = 'PEERING'
    MP_PEERING_ATTR = 'MP-PEERING'

    @staticmethod
    def _parsePeering(p):
        return p.strip().split(' ')[0]

    @staticmethod
    def isPeeringSet(name):
        """
        Returns True when the name appears to be as-set name (=key)
        according to RPSL specs.
        """
        return str(name).upper().find('PRNG-') > -1

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.peering_set = None
        self.peering = []
        self.mp_peering = []

        for (a, v) in RpslObject.splitLines(self.text):
            if a == self.PEERINGSET_ATTR:
                self.peering_set = v.strip().upper()

            elif a == self.PEERING_ATTR:
                self.peering.append(PeeringSetObject._parsePeering(v))

            elif a == self.MP_PEERING_ATTR:
                self.mp_peering.append(PeeringSetObject._parsePeering(v))
            else:
                pass  # ignore unrecognized lines

        if not self.peering_set:
            raise Exception("Can not create AsSetObject out of text: " + str(textlines))

    def getKey(self):
        return self.peering_set

    # def recursiveMatch(self, target, hashObjDir, recursionList=None):
    #     """
    #     This methods does recusion in the objects peering and mp-peering sections
    #     and tries to find analyser with the target identifier.
    #
    #     This is being used by filter matching instead of full filter recursion because we
    #     know that this type of object could hold only ASNs or references to another
    #     peering-sets and therefore full filter recursion is not needed and this special
    #     recursion offers mild speedup.
    #     """
    #     if recursionList == None:
    #         recursionList = []
    #
    #     # common.d("PeeringSetObject recursiveMatch: target", target, 'in', self.getKey(),
    #     #          'recursionList', recursionList)
    #
    #     # prevent recusion loop
    #     if self.getKey() in recursionList:
    #         return False
    #     recursionList.append(self.getKey())
    #
    #     if target in self.peering or target in self.mp_peering:
    #         return True
    #
    #     for m in (self.peering + self.mp_peering):
    #         if self.isPeeringSet(m) and m in hashObjDir.table:
    #             r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
    #             if r:
    #                 return True
    #
    #     return False

    def __str__(self):
        return 'PeeringSetObject: %s -< %s mp: %s' % (self.peering_set, str(self.peering), str(self.mp_peering))


class FilterSetObject(RpslObject):
    """ Internal representation of filter-set RPSL object. """

    FILTERSET_ATTR = 'FILTER-SET'
    FILTER_ATTR = 'FILTER'
    MP_FILTER_ATTR = "MP-FILTER"

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.filter_set = None
        self.filter = None
        self.mp_filter = None

        for (a, v) in RpslObject.splitLines(self.text):
            if a == self.FILTERSET_ATTR:
                self.filter_set = v.strip().upper()

            elif a == self.FILTER_ATTR:
                self.filter = v.strip()

            elif a == self.MP_FILTER_ATTR:
                self.mp_filter = v.strip()

            else:
                pass  # ignore unrecognized lines

        if not self.filter_set:
            raise Exception("Can not create FilterSetObject out of text: " + str(textlines))

    @staticmethod
    def isFltrSet(fltrsetid):
        """ Returns True when the name appears to be filter-set name (=key)
        according to RPSL specs. """
        return fltrsetid.upper().find('FLTR-') > -1

    def getKey(self):
        return self.filter_set

    def __str__(self):
        f = None
        if self.filter:
            f = str(self.filter)
        if self.mp_filter:
            if f:
                f += ' + '
            else:
                f = ''
            f += str(self.mp_filter)
        return 'FilterSetbject: %s -< %s' % (self.filter_set, f)


class RouteSetObject(RpslObject):
    """ Internal representation of route-set RPSL object. """

    ROUTESET_ATTR = 'ROUTE-SET'
    MEMBERS_ATTR = 'MEMBERS'
    MP_MEMBERS_ATTR = "MP-MEMBERS"

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.route_set = None
        self.members = []
        self.mp_members = []

        for (a, v) in RpslObject.splitLines(self.text):
            if a == self.ROUTESET_ATTR:
                self.route_set = v.strip().upper()

            elif a == self.MEMBERS_ATTR:
                self.members += [r.strip() for r in v.strip().split(',')]

            elif a == self.MP_MEMBERS_ATTR:
                self.mp_members += [r.strip() for r in v.strip().split(',')]

            else:
                pass  # ignore unrecognized lines

        if not self.route_set:
            raise Exception("Can not create RouteSetObject out of text: " + str(textlines))

    @staticmethod
    def isRouteSet(rsid):
        """ Returs True when the name appears to be route-set name (=key)
        according to RPSL specs. """
        return str(rsid).find('RS-') > -1

    def getKey(self):
        return self.route_set

    def __str__(self):
        return 'RouteSetbject: %s -< %s + %s' % (self.route_set, str(self.members), str(self.mp_members))


##################
#   MY PART      #
##################
class PeerAS:
    def __init__(self, autnum):
        self.origin = autnum
        self.v4Filters = {'imports': "", 'exports': ""}
        self.v6Filters = {'imports': "", 'exports': ""}
        self.peeringPoints = dict()

    def appendImportFilters(self, filters, mp=False):
        if filters is not None:
            if not mp:
                # self.v4Filters['imports'] = set(filters)
                self.v4Filters['imports'] = filters
            else:
                # self.v6Filters['imports'] = set(filters)
                self.v6Filters['imports'] = filters

    def appendExportFilters(self, filters, mp=False):
        if filters is not None:
            if not mp:
                # self.v4Filters['exports'] = set(filters)
                self.v4Filters['exports'] = filters
            else:
                # self.v6Filters['exports'] = set(filters)
                self.v6Filters['exports'] = filters

    def appendPeeringPoint(self, PeeringPoint):
        self.peeringPoints[PeeringPoint.getKey()] = PeeringPoint

    def returnPeeringPoint(self, pkey):
        return self.peeringPoints[pkey]

    def checkPeeringPointKey(self, pkey):
        if pkey in self.peeringPoints:
            return True
        return False

    def getAllFilters(self):

        filter_set = set()
        # if self.ipv4:
        filter_set.update(self.v4Filters.get('imports'))
        filter_set.update(self.v4Filters.get('exports'))
        # if self.ipv6:
        filter_set.update(self.v6Filters.get('imports'))
        filter_set.update(self.v6Filters.get('exports'))

        return filter_set

        # def __str__(self):
        #     if not self.ipv6:
        #         return "Peering %s with remote %s at local %s " % (self.origin, self.remoteIPv4, self.localIPv4)
        #     else:
        #         return "Peering %s with remote (%s ~ %s) at local (%s ~ %s) " % (
        #         self.origin, self.remoteIPv4, self.remoteIPv6,
        #         self.localIPv4, self.localIPv6)


class PeeringPoint:
    def __init__(self, mp):
        self.local_ip = ""
        self.remote_ip = ""
        self.mp = mp
        self.actions_in = PolicyActionList('import')
        self.actions_out = PolicyActionList('export')

    def appendAddresses(self, local, remote):
        self.local_ip = local
        self.remote_ip = remote

    def getKey(self):
        """
        Pseudo key generator for dictionary appending
        if no IPs are present then actions_in are applied in
        every ingress/egress point of the domain
        """
        return str(self.local_ip) + "|" + str(self.remote_ip)

    def __str__(self):
        yield "Local_IP: %s Remote_IP: %s" % (self.local_ip, self.remote_ip)


class PeerObjDir:
    def __init__(self):
        self.peerTable = {}

    def appentPeering(self, peerAs):
        self.peerTable[peerAs.origin] = peerAs

    def returnPeering(self, asnum):
        if asnum in self.peerTable.keys():
            return self.peerTable[asnum]
        else:
            raise Exception('Peer AS does not exist')

    def enumerateObjs(self):
        for k in self.peerTable.keys():
            for o in self.peerTable[k]:
                yield o


class peerFilter:
    """
    We define 4 types of resolved (or not resolved) filters:
    0: No type has been assigned, therefore the filter has not been resolved and shall be rejected.
    1: Prefix_List (the filter is resolved in a complete prefix list and can be transferred into the router)
    2: AS_Path (The filter is an AS path expression and needs to be copied into the router accordingly)
    3: REGEX (The filter is a Regular Expression and needs to be transferred in the router correctly)
    4: COMBI (The filter is a combination of the other types)
    """

    def __init__(self, hv, expr):
        self.hashValue = hv
        self.expression = expr
        self.type = 0

    def __str__(self):
        yield str(self.hashValue) + " -> " + self.expression


class peerFilterDir:
    def __init__(self):
        self.filterTable = {}

    def appendFilter(self, peerFilter):
        self.filterTable[peerFilter.hashValue] = peerFilter

    def returnFilter(self, hashVal):
        return self.filterTable[hashVal]

    def number_of_filters(self):
        return len(self.filterTable.keys())
