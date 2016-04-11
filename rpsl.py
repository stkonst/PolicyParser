__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl) '
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com) '
import re

import errors


#  TODO Recheck all regex later for fine tuning.
ASN_MATCH = re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH = re.compile('^\{([^}]*)\}(\^[0-9+-]+)?$')
PFX_MATCH = re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9+-]+)?$')
PFX_RANGE_OPERATOR = re.compile('^\^[0-9+-]+$')
AS_SET_MATCH = re.compile('^(AS\d+:)*AS-(\w|-)+$')
RS_SET_MATCH = re.compile('^RS-(\w|-)+$')
RTR_SET_MATCH = re.compile('^RTR-(\w|-)+$')
FLTR_SET_MATCH = re.compile('^FLTR-(\w|-)+$')


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
    """

    ROUTE_ATTR = 'ROUTE'
    ORIGIN_ATTR = 'ORIGIN'
    # MEMBEROF_ATTR = 'MEMBER-OF'

    def __init__(self, route, origin):
        self.route = route
        self.origin = origin

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
            raise errors.AppendFilterError('Failed to insert Route object to dictionary')

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

    def __init__(self, asnum):
        self.origin = asnum
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

    def __init__(self, setname):
        RpslObject.__init__(self)
        self.as_set = setname
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

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.peering_set = None
        self.peering = []
        self.mp_peering = []

    def getKey(self):
        return self.peering_set

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

    def __init__(self, setname):
        RpslObject.__init__(self)
        self.route_set = setname
        self.members = RouteObjectDir()
        self.mp_members = RouteObjectDir()
        self.RSSetsDir = set()

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
        # table scheme: {hash-value: direction}
        self.filters = dict()
        self.mp_filters = dict()
        self.peeringPoints = dict()

    def appendFilter(self, info, mp):

        """ It appends only the hash value of the Peer filter
            that has been created and stored previously.
        """
        # info set(direction, afi, hash)

        if mp:
            self.mp_filters[info[2]] = info[0]

        else:
            self.filters[info[2]] = info[0]

    def appendPeeringPoint(self, PeeringPoint):
        self.peeringPoints[PeeringPoint.getKey()] = PeeringPoint

    def returnPeeringPoint(self, pkey):
        return self.peeringPoints[pkey]

    def checkPeeringPointKey(self, pkey):
        if pkey in self.peeringPoints:
            return True
        return False


class PeeringPoint:
    def __init__(self, afi):
        self.local_ip = ""
        self.remote_ip = ""
        self.actions_in = PolicyActionList('import')
        self.actions_out = PolicyActionList('export')

    def appendAddresses(self, local, remote):
        self.local_ip = local
        self.remote_ip = remote

    def getKey(self):
        """
        Pseudo key generator for dictionary appending.
        If no IPs are present then actions_in are applied in
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
            "TODO: Make it custom error"
            raise errors.ASDiscoveryError('Peer AS does not exist')

    def enumerateObjs(self):
        for k in self.peerTable.keys():
            yield self.peerTable[k]


class peerFilter:
    def __init__(self, hv, afi, expr):
        self.hashValue = hv
        self.afi = afi
        self.expression = expr
        self.statements = ""

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
