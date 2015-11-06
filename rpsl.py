__author__ = 'stavros'
__author__ += 'Tomas Hlavacek (tmshlvck@gmail.com)'


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


class PolicyAction(object):
    # TODO Create a more detailed Action Machinery (see spliter)
    def __init__(self):
        self.order = 0
        self.rp_attr = ''
        self.rp_oper = ''
        self.rp_val = ''

    def assignValues(self, attr, operator, value):
        self.rp_attr = attr
        self.rp_oper = operator
        self.rp_val = value

    def __str__(self):
        return '%s%s%s' % (self.rp_attr, self.rp_oper, self.rp_val)


class PolicyActionList:
    def __init__(self):
        self.actionList = list()

    def appendAction(self, PolicyAction):
        self.actionList.append(PolicyAction)


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

    def __init__(self, textlines):
        RpslObject.__init__(self, textlines)
        self.as_set = None
        self.members = []

        for (a, v) in RpslObject.splitLines(self.text):
            if a == self.ASSET_ATTR:
                self.as_set = v.strip().upper()

            elif a == self.MEMBERS_ATTR:
                # flatten the list in case we have this:
                # members: AS123, AS456, AS-SOMETHING
                # members: AS234, AS-SMTHNG
                for m in AsSetObject._parseMembers(v):
                    self.members.append(m)

            else:
                pass  # ignore unrecognized lines

        if not self.as_set:
            raise Exception("Can not create AsSetObject out of text: " + str(textlines))

    def getKey(self):
        return self.as_set

    def recursiveMatch(self, target, hashObjDir, recursionList=None):
        """
        This methods does recursion in the objects members and tries to find match
        with the target identifier.

        This is being used by filter matching instead of full filter recursion because we
        know that this type of object could hold only ASNs or references to another
        as-sets and therefore full filter recursion is not needed and this special
        recursion offers mild speedup.
        """

        if recursionList == None:
            recursionList = []

        # common.d("AsSetObject recursiveMatch: target", target, 'in', self.getKey(), 'recursionList', recursionList)
        #        common.d("Members:", self.members)
        # prevent recusion loop
        if self.getKey() in recursionList:
            return False
        recursionList.append(self.getKey())

        if target in self.members:
            return True

        for m in self.members:
            if self.isAsSet(m) and m in hashObjDir.table:
                r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
                if r:
                    return True

        return False

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

    def recursiveMatch(self, target, hashObjDir, recursionList=None):
        """
        This methods does recusion in the objects peering and mp-peering sections
        and tries to find match with the target identifier.

        This is being used by filter matching instead of full filter recursion because we
        know that this type of object could hold only ASNs or references to another
        peering-sets and therefore full filter recursion is not needed and this special
        recursion offers mild speedup.
        """
        if recursionList == None:
            recursionList = []

        # common.d("PeeringSetObject recursiveMatch: target", target, 'in', self.getKey(),
        #          'recursionList', recursionList)

        # prevent recusion loop
        if self.getKey() in recursionList:
            return False
        recursionList.append(self.getKey())

        if target in self.peering or target in self.mp_peering:
            return True

        for m in (self.peering + self.mp_peering):
            if self.isPeeringSet(m) and m in hashObjDir.table:
                r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
                if r:
                    return True

        return False

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


class PeerAS(object):
    def __init__(self, autnum):
        self.ipv4 = False
        self.ipv6 = False
        self.origin = autnum
        self.localIPv4 = None
        self.remoteIPv4 = None
        self.localIPv6 = None
        self.remoteIPv6 = None
        self.v4imports = {'filters': set(), 'actions': list()}
        self.v4exports = {'filters': set(), 'actions': list()}
        self.v6imports = {'filters': set(), 'actions': list()}
        self.v6exports = {'filters': set(), 'actions': list()}

    def updatePeerIPs(self, local, remote, mp):
        if mp:
            self.localIPv6 = local
            self.remoteIPv6 = remote
        else:
            self.localIPv4 = local
            self.remoteIPv4 = remote

    def appendImportActions(self, actions, mp=False):
        if actions is not None:
            if not mp:
                self.v4imports['actions'] = list(actions)
            else:
                self.v6imports['actions'] = list(actions)

    def appendImportFilters(self, filters, mp=False):
        if filters is not None:
            if not mp:
                self.v4imports['filters'] = set(filters)
            else:
                self.v6imports['filters'] = set(filters)

    def appendExportActions(self, actions, mp=False):
        if actions is not None:
            if not mp:
                self.v4exports['actions'] = list(actions)
            else:
                self.v6exports['actions'] = list(actions)

    def appendExportFilters(self, filters, mp=False):
        if filters is not None:
            if not mp:
                self.v4exports['filters'] = set(filters)
            else:
                self.v6exports['filters'] = set(filters)

    def getAllFilters(self):

        filter_set = set()
        if self.ipv4:
            filter_set.update(self.v4imports.get('filters'))
            filter_set.update(self.v4exports.get('filters'))
        if self.ipv6:
            filter_set.update(self.v6imports.get('filters'))
            filter_set.update(self.v6exports.get('filters'))

        return filter_set

    def __str__(self):
        if not self.ipv6:
            return "Peering %s with remote %s at local %s " % (self.origin, self.remoteIPv4, self.localIPv4)
        else:
            return "Peering %s with remote (%s ~ %s) at local (%s ~ %s) " % (
            self.origin, self.remoteIPv4, self.remoteIPv6,
            self.localIPv4, self.localIPv6)


class PeerObjDir(object):
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
