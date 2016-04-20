import logging
import xml.etree.cElementTree as et

import rpsl
import analyzer
import parsers

depth_limit = 15


class filterResolver:
    def __init__(self, items, Communicator, ipv6_enabled, blist):

        self.peerFilters = items
        self.ipv6_enabled = ipv6_enabled
        self.communicator = Communicator
        self.black_list = blist

        # A set that contains all the AS-Sets that we discover via parsing
        # and need to be translated into prefix-lists.
        self.ASSetList = set()

        # A global data pool that contains all the AS-SETs that we discovered
        # (included nested ones) to minimise interaction with RIPE-DB (double resolving).
        self.asSetdir = rpsl.AsSetObjectDir()

        # A set that contains all the RS-Sets that we discover via parsing
        # and need to be translated into prefix-lists.
        self.RSSetList = set()

        # A global data pool that contains all the RS-SETs that we discovered
        # (included nested ones) to minimise interaction with RIPE-DB (double resolving).
        self.RSSetDir = rpsl.RouteSetObjectdir()

        # A set that contains all the ASNs that we discover via parsing
        # and need to be translated into prefix-lists.
        self.ASNList = set()

        # A global pool that contains all the ASN objects (including nested ones)
        # to minimise interaction with RIPE-DB (double resolving).
        self.dataPool = rpsl.ASNObjectDir()

    def resolveFilters(self):

        for pf in self.peerFilters.enumerateObjs():
            # Analyser will analyse the filter and recognise the elements that compose it
            output_queue, new_ASNs, new_asSets, new_rsSets = analyzer.analyze_filter(pf.expression)

            for a in new_ASNs:
                self.ASNList.add(a)
                obj = self._resolveASN(a)
                if obj is not None:
                    # Possibility to get a garbage AS-num is quite high. In that case we receive None.
                    self.dataPool.appendASNObj(obj)

            for s in new_asSets:
                self.ASSetList.add(s)
                self._resolveASSet(s, -1)

            for r in new_rsSets:
                self.RSSetList.add(r)
                self._resolveRSSet(r, -1)

            pf.statements = analyzer.compose_filter(output_queue)

            # logging.debug("ASN: %s AS-SET %s RS-SET %s" % (
            # len(self.dataPool.asnObjDir), len(self.asSetdir.asSetObjDir), len(self.RSSetDir.RouteSetObjDir)))

    def _resolveASN(self, asn):

        try:
            ans = self.communicator.getRoutesByAutnum(asn, ipv6_enabled=self.ipv6_enabled)
            if ans is None:
                raise LookupError

            dbObj = et.fromstring(ans)
            asnObj = rpsl.ASNObject(asn)
            ap = parsers.ASNParser(asnObj, True)
            ap.extractRoutes(dbObj)
            return asnObj

        except LookupError:
            logging.error("No Object found for %s " % asn)
            return None

        except Exception as e:
            logging.warning("Failed to resolve DB object %s. %s " % (asn, e))
            return None

    def _resolveASSet(self, setname, depth):

        if depth == depth_limit:
            logging.warning("Emergency exit. Too much recursion.")
            return
        depth += 1

        try:
            ans = self.communicator.getFilterSet(setname)
            if ans is None:
                raise LookupError

            dbObj = et.fromstring(ans)
            setObj = rpsl.AsSetObject(setname)
            aspa = parsers.ASSetParser(setObj)

            """ First variable refers to AS-SETs that are included and need to be resolved (recursively).
                Second variable refers to ASNs that are included and need to be resolved.
            """
            new_ASsets, new_ASNs = aspa.parseMembers(dbObj, self.dataPool, self.asSetdir)
            s = '"'
            for i in range(0, depth):
                s += "-"
            logging.debug(
                "{}>Found {} new ASNs and {} new AS-SETs in {}".format(s, len(new_ASNs), len(new_ASsets), setname))

            for a in new_ASNs:
                o = self._resolveASN(a)
                if o is not None:
                    self.dataPool.appendASNObj(o)

            for u in new_ASsets:
                self._resolveASSet(u, depth)

        except LookupError:
            logging.error("No Object found for {} ".format(setname))
            return

        except Exception as e:
            logging.warning("Failed to resolve DB object {}. {} ".format(setname, e))
            return

    def _resolveRSSet(self, rsname, depth):

        depth += 1
        try:
            dbObj = et.fromstring(self.communicator.getFilterSet(rsname))
            setObj = rpsl.RouteSetObject(rsname)
            rspa = parsers.RSSetParser(setObj, self.ipv6_enabled)

            '''The variable refers to nested RS-SETs that need to be resolved recursively.'''
            new_rsSets = rspa.parseMembers(dbObj, self.RSSetDir)
            for u in new_rsSets:
                self._resolveRSSet(u, depth)

        except Exception as e:
            logging.error("Failed to fully resolve -> {}. {}".format(rsname, e))
            return
