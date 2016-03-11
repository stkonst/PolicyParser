__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl) '
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com) '
import re

#  TODO Recheck all regex later for fine tuning.
ASN_MATCH = re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH = re.compile('^\{([^}]*)\}(\^[0-9+-]+)?$')
PFX_MATCH = re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9+-]+)?$')
PFX_RANGE_OPERATOR = re.compile('^\^[0-9+-]+$')
AS_SET_MATCH = re.compile('^(AS\d+:)*AS-(\w|-)+$')
RS_SET_MATCH = re.compile('^RS-(\w|-)+$')
RTR_SET_MATCH = re.compile('^RTR-(\w|-)+$')
FLTR_SET_MATCH = re.compile('^FLTR-(\w|-)+$')

# Regex operators
# {m} {m,} {m,n}    --> ~?\{\d+(?:,\d*)?\}
# OR
# * + ? ~ ~* ~+     --> (?:\?|~?(?:\*|\+)?)
regex_ops = '(?:(?:\?|~?(?:\*|\+)?)|~?\{\d+(?:,\d*)?\})?'
AS_PATH_MEMBER_MATCH = [ # ASN with regex operators
                        re.compile("^\^?{asn}{regexops}\$?$".format(asn='AS[0-9]+',regexops=regex_ops)),
                        # AS_SET with regex operators
                        re.compile("^\^?{as_set}{regexops}\$?$".format(as_set='(AS\d+:)*AS-(\w|-)*',regexops=regex_ops)),
                        # '.' with regex operators
                        re.compile("^\^?\.{regexops}\$?$".format(regexops=regex_ops)),]


def is_ASN(value):
    return ASN_MATCH.match(str(value).strip()) != None


def is_pfx_filter(value):
    return PFX_FLTR_MATCH.match(value) != None


def is_pfx(value):
    return PFX_MATCH.match(value) != None


def is_pfx_range_operator(value):
    return PFX_RANGE_OPERATOR.match(value) != None


def is_AS_set(value):
    return AS_SET_MATCH.match(value) != None


def is_rtr_set(value):
    return RTR_SET_MATCH.match(value) != None


def is_rs_set(value):
    return RS_SET_MATCH.match(value) != None


def is_fltr_set(value):
    return FLTR_SET_MATCH.match(value) != None


def is_as_path_member(value):
    valid = False
    for regex in AS_PATH_MEMBER_MATCH:
        if regex.match(value):
            valid = True
            break
    return valid


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
    # MEMBEROF_ATTR = 'MEMBER-OF'

    def __init__(self, route, origin):
        self.route = route
        self.origin = origin
        # self.memberof = []

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

    def checkRouteExists(self, route, v6=False):
        if v6:
            if self.originTableV6.has_key(route):
                return True
            return False
        else:
            if self.originTable.has_key(route):
                return True
            return False


class ASNObject(RpslObject):
    """
    Internal representation of an AS
    """

    def __init__(self, asnum, hv):
        self.origin = asnum
        self.hash = hv
        self.routeObjDir = RouteObjectDir()

    def getKey(self):
        return self.origin

    def __str__(self):
        return str(self.origin)

    def appendRouteObj(self, RouteObject):
        self.routeObjDir[RouteObject.getKey()] = RouteObject

    def ASN_has_route(self, RouteObject, v6=False):
        if v6:
            if self.routeObjDir.originTableV6.has_key(RouteObject.getKey()):
                return True
            return False
        else:
            if self.routeObjDir.originTable.has_key(RouteObject.getKey()):
                return True
            return False


class ASNObjectDir:

    def __init__(self):
        self.asnObjDir = {}

    def appendASNObj(self, ASNObject):
        self.asnObjDir[ASNObject.getKey()] = ASNObject


class PolicyAction:
    # TODO Create a more detailed Action Machinery (see george code)
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

    def __init__(self, setname, hv):
        RpslObject.__init__(self)
        self.as_set = setname
        self.hash = hv
        self.ASNmembers = set()
        self.ASSetmember = set()

    def getKey(self):
        return self.as_set

    def __str__(self):
        return 'AsSetObject: %s ' % self.as_set


class AsSetObjectDir:
    def __init__(self):
        self.asSetObjDir = {}

    def appendAsSetObj(self, AsSetObject):
        self.asSetObjDir[AsSetObject.getKey()] = AsSetObject

    def checkAsSetExists(self, AsSetObject):
        if AsSetObject.getKey() in self.asSetObjDir.keys():
            return True
        return False


class PeeringSetObject(RpslObject):
    """ Internal representation of prng-set RPSL object. """

    PEERINGSET_ATTR = 'PEERING-SET'
    PEERING_ATTR = 'PEERING'
    MP_PEERING_ATTR = 'MP-PEERING'

    @staticmethod
    def _parsePeering(p):
        return p.strip().split(' ')[0]

    # @staticmethod
    # def isPeeringSet(name):
    #     """
    #     Returns True when the name appears to be as-set name (=key)
    #     according to RPSL specs.
    #     """
    #     return str(name).upper().find('PRNG-') > -1

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.peering_set = None
        self.peering = []
        self.mp_peering = []

        # for (a, v) in RpslObject.splitLines(self.text):
        #     if a == self.PEERINGSET_ATTR:
        #         self.peering_set = v.strip().upper()
        #
        #     elif a == self.PEERING_ATTR:
        #         self.peering.append(PeeringSetObject._parsePeering(v))
        #
        #     elif a == self.MP_PEERING_ATTR:
        #         self.mp_peering.append(PeeringSetObject._parsePeering(v))
        #     else:
        #         pass  # ignore unrecognized lines
        #
        # if not self.peering_set:
        #     raise Exception("Can not create AsSetObject out of text: " + str(textlines))

    def getKey(self):
        return self.peering_set

    # def recursiveMatch(self, target, hashObjDir, recursionList=None):
    #     """
    #     This methods does recusion in the objects peering and mp-peering sections
    #     and tries to find interpreter with the target identifier.
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

        # for (a, v) in RpslObject.splitLines(self.text):
        #     if a == self.FILTERSET_ATTR:
        #         self.filter_set = v.strip().upper()
        #
        #     elif a == self.FILTER_ATTR:
        #         self.filter = v.strip()
        #
        #     elif a == self.MP_FILTER_ATTR:
        #         self.mp_filter = v.strip()
        #
        #     else:
        #         pass  # ignore unrecognized lines
        #
        # if not self.filter_set:
        #     raise Exception("Can not create FilterSetObject out of text: " + str(textlines))

    # @staticmethod
    # def isFltrSet(fltrsetid):
    #     """ Returns True when the name appears to be filter-set name (=key)
    #     according to RPSL specs. """
    #     return fltrsetid.upper().find('FLTR-') > -1

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

    def __init__(self, setname, hv):
        RpslObject.__init__(self)
        self.route_set = setname
        self.hash = hv
        self.members = RouteObjectDir()
        self.mp_members = RouteObjectDir()
        self.RSSetsDir = {}

    def getKey(self):
        return self.route_set

    def __str__(self):
        return 'RouteSetbject: %s ' % self.route_set


class RouteSetObjectdir:
    def __init__(self):
        self.RouteSetObjDir = {}

    def appendRouteSetObj(self, RouteSetObject):
        self.RouteSetObjDir[RouteSetObject.getKey()] = RouteSetObject

##################
##################


class PeerAS:
    def __init__(self, autnum):
        self.origin = autnum
        # table scheme: {hash-value: (direction, afi)}
        self.v4Filters = dict()
        self.v6Filters = dict()
        self.peeringPoints = dict()

    def appendFilter(self, info, mp):

        # info set(direction, afi, hash)
        if 'IPV4' in info[1]:
            self.v4Filters[info[2]] = (info[0], info[1])
        elif 'IPV6' in info[1]:
            self.v6Filters[info[2]] = (info[0], info[1])
        else:
            if mp:
                self.v6Filters[info[2]] = (info[0], info[1])
            else:
                raise Exception("Unsupported AFI found")

    def appendPeeringPoint(self, PeeringPoint):
        self.peeringPoints[PeeringPoint.getKey()] = PeeringPoint

    def returnPeeringPoint(self, pkey):
        return self.peeringPoints[pkey]

    def checkPeeringPointKey(self, pkey):
        if pkey in self.peeringPoints:
            return True
        return False


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
        return "Local_IP: %s Remote_IP: %s" % (self.local_ip, self.remote_ip)


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
            yield self.peerTable[k]


class peerFilter:
    """
    We define 4 types of resolved (or not resolved) fltrExpressions:
    0: Unresolved (could not be expanded) filter, therefore it shall be rejected or decided by the user.
    1: Prefix_List (the filter is resolved in a complete prefix list and can be transferred into the router)
    2: CP The filter is an expression and needs to be copied into the router accordingly
    3: COMBI (The filter is a combination of the other types)
    """

    def __init__(self, hv, afi, expr):
        self.hashValue = hv
        self.expression = expr
        self.queue = ""
        self.afi = afi
        self.type = 0

    def __str__(self):
        return str(self.hashValue) + " -> " + self.expression


class peerFilterDir:
    def __init__(self):
        self.filterTable = {}

    def appendFilter(self, peerFilter):
        self.filterTable[peerFilter.hashValue] = peerFilter

    def returnFilter(self, hashVal):
        return self.filterTable[hashVal]

    def number_of_filters(self):
        return len(self.filterTable.keys())

    def enumerateObjs(self):
        for k in self.filterTable.keys():
            yield self.filterTable[k]
