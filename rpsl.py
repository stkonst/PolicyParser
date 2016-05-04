import re

import errors


#  TODO Recheck all regex later for fine tuning.
ASN_MATCH = re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH = re.compile('^\{([^}]*)\}(\^[0-9+-]+)?$')
PFX_MATCH = re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9+-]+)?$')
RANGE_OPERATOR = re.compile('^\^[0-9+-]+$')
AS_SET_MATCH = re.compile('^(?:AS\d+:)*(?:AS-(?:\w|-)+:?)+(?::AS\d+)*$')
RS_SET_MATCH = re.compile('^(?:AS\d+:)*(?:RS-(?:\w|-)+:?)+(?::AS\d+)*$')
RS_SET_WITH_RANGE_MATCH = re.compile('^(?:AS\d+:)*(?:RS-(?:\w|-)+:?)+(?::AS\d+)*(?:\^[0-9+-]+)?$')
RTR_SET_MATCH = re.compile('^(?:AS\d+:)*(?:RTR-(?:\w|-)+:?)+(?::AS\d+)*$')
FLTR_SET_MATCH = re.compile('^(?:AS\d+:)*(?:FLTR-(?:\w|-)+:?)+(?::AS\d+)*$')


regex_ops = '(?:(?:\?|~?(?:\*|\+)?)|~?\{\d+(?:,\d*)?\})?'
AS_PATH_MEMBER_MATCH = [  # ASN or set of ASNs with regex operators
                        re.compile("^\^?{asn}{regexops}\$?$".format(asn='[[^]{0,2}AS[0-9]+\]?', regexops=regex_ops)),
                        # AS_SET with regex operators
                        re.compile("^\^?{as_set}{regexops}\$?$".format(as_set='(?:AS\d+:)*(?:AS-(?:\w|-)+:?)+(?::AS\d+)*', regexops=regex_ops)),
                        # '.' with regex operators
                        re.compile("^\^?\.{regexops}\$?$".format(regexops=regex_ops)), ]


def is_ASN(value):
    return ASN_MATCH.match(str(value).strip()) is not None


def is_pfx_filter(value):
    return PFX_FLTR_MATCH.match(value) is not None


def is_pfx(value):
    return PFX_MATCH.match(value) is not None


def is_range_operator(value):
    return RANGE_OPERATOR.match(value) is not None


def is_AS_set(value):
    return AS_SET_MATCH.match(value) is not None


def is_rtr_set(value):
    return RTR_SET_MATCH.match(value) is not None


def is_rs_set(value):
    return RS_SET_MATCH.match(value) is not None


def is_rs_set_with_range(value):
    return RS_SET_WITH_RANGE_MATCH.match(value) is not None


def is_fltr_set(value):
    return FLTR_SET_MATCH.match(value) is not None


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

    def get_key(self):
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

    def __init__(self, route, origin):
        self.route = route
        self.origin = origin

    def get_key(self):
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
        self.origin_table = {}
        self.ipv6 = ipv6
        if self.ipv6:
            self.origin_table_v6 = {}

    def append_route_obj(self, route_object):
        if route_object.ROUTE_ATTR == 'ROUTE6':
            self.origin_table_v6[route_object.get_key] = route_object
        elif route_object.ROUTE_ATTR == 'ROUTE':
            self.origin_table[route_object.get_key] = route_object
        else:
            raise errors.AppendFilterError('Failed to insert Route object to dictionary')


class ASObject(RpslObject):
    """
    Internal representation of an AS
    """

    def __init__(self, asnum):
        self.origin = asnum
        self.route_obj_dir = RouteObjectDir()

    def get_key(self):
        return self.origin

    def __str__(self):
        return str(self.origin)

    def append_route_obj(self, route_object):
        self.route_obj_dir[route_object.get_key()] = route_object


class AsnObjectDir:
    def __init__(self):
        self.data = {}

    def append_ASN_obj(self, ASN_object):
        self.data[ASN_object.get_key()] = ASN_object


class PolicyAction:
    # TODO Create a more detailed Action Machinery (see george code)
    def __init__(self, i, attr, oper, val):
        self.order = i
        self.rp_attr = attr
        self.rp_operator = oper
        self.rp_value = val

    def __str__(self):
        return '{}{}{}'.format(self.rp_attr, self.rp_operator, self.rp_value)


class PolicyActionList:
    def __init__(self, direction):
        self.data = dict()
        self.direction = direction

    def append_action(self, policy_action):
        self.data[policy_action.order] = policy_action


# Set-* objects

class AsSetObject(RpslObject):
    """ Internal representation of as-set RPSL object. """

    ASSET_ATTR = 'AS-SET'
    MEMBERS_ATTR = 'MEMBERS'

    def __init__(self, setname):
        RpslObject.__init__(self)
        self.as_set = setname
        self.ASN_members = set()
        self.AS_set_members = set()

    def get_key(self):
        return self.as_set

    def __str__(self):
        return 'AsSetObject: {} '.format(self.as_set)


class AsSetObjectDir:
    def __init__(self):
        self.data = {}

    def append_AS_set_obj(self, AS_set_object):
        self.data[AS_set_object.get_key()] = AS_set_object


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

    def get_key(self):
        return self.peering_set

    def __str__(self):
        return 'PeeringSetObject: {} -< {} mp: {}'.format(self.peering_set, str(self.peering), str(self.mp_peering))


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

    def get_key(self):
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
        return 'FilterSetbject: {} -< {}'.format(self.filter_set, f)


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
        self.RSes_dir = set()

    def get_key(self):
        return self.route_set

    def __str__(self):
        return 'RouteSetbject: {} '.format(self.route_set)


class RouteSetObjectdir:
    def __init__(self):
        self.data = {}

    def append_route_set_obj(self, route_set_object):
        self.data[route_set_object.get_key()] = route_set_object


class PeerAS:
    def __init__(self, autnum):
        self.origin = autnum
        # table scheme: {hash-value: direction}
        self.filters = dict()
        self.mp_filters = dict()
        self.peering_points = dict()

    def append_filter(self, info, mp):

        """ It appends only the hash value of the Peer filter
            that has been created and stored previously.
        """
        # info set(direction, afi, hash)

        if mp:
            self.mp_filters[info[2]] = info[0]

        else:
            self.filters[info[2]] = info[0]

    def append_peering_point(self, peering_point):
        self.peering_points[peering_point.get_key()] = peering_point

    def return_peering_point(self, pkey):
        return self.peering_points[pkey]

    def check_peering_point_key(self, pkey):
        return pkey in self.peering_points


class PeeringPoint:
    def __init__(self):
        self.local_ip = ""
        self.remote_ip = ""
        self.actions_in = PolicyActionList('import')
        self.actions_out = PolicyActionList('export')

    def append_addresses(self, local, remote):
        self.local_ip = local
        self.remote_ip = remote

    def get_key(self):
        """Pseudo key generator for dictionary appending.
        If no IPs are present then actions_in are applied in
        every ingress/egress point of the domain
        """

        return str(self.local_ip) + "|" + str(self.remote_ip)

    def __str__(self):
        return "Local_IP: {} Remote_IP: {}".format(self.local_ip, self.remote_ip)


class PeerObjDir:
    def __init__(self):
        self.peer_table = {}

    def append_peering(self, peer_AS):
        self.peer_table[peer_AS.origin] = peer_AS

    def return_peering(self, asnum):
        if asnum in self.peer_table.keys():
            return self.peer_table[asnum]
        else:
            raise errors.ASDiscoveryError('Peer AS does not exist')

    def enumerate_objs(self):
        for k in self.peer_table.itervalues():
            yield k


class PeerFilter:
    def __init__(self, hv, afi, expr):
        self.hash_value = hv
        self.afi = afi
        self.expression = expr
        self.statements = ""

    def __str__(self):
        return str(self.hash_value) + " -> " + self.expression


class PeerFilterDir:
    def __init__(self):
        self.filter_table = {}

    def append_filter(self, peer_filter):
        self.filter_table[peer_filter.hash_value] = peer_filter

    def return_filter(self, hv):
        return self.filter_table[hv]

    def number_of_filters(self):
        return len(self.filter_table)

    def enumerate_objs(self):
        for k in self.filter_table.itervalues():
            yield k
