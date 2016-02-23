__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl) '
__author__ += 'George Thessalonikefs (george@nlnetlabs.nl) '
import xml.etree.ElementTree as et

import rpsl
import parsers
import libtools as tools

depth_limit = 15


class filterResolver:
    def __init__(self, items, Communicator, ipv6_enabled):
        self.peerFilters = items
        self.ipv6_enabled = ipv6_enabled
        self.communicator = Communicator
        self.RSSetDir = rpsl.RouteSetObjectdir()
        self.ASNdir = rpsl.ASNObjectDir()
        self.asSetdir = rpsl.AsSetObjectDir()

    def resolveFilters(self):

        for pf in self.peerFilters.filterTable.itervalues():
            'TODO: Maybe a try-except will help better'
            self.recogniseFilter(pf)

    def resolveASN(self, asn):

        try:
            ans = self.communicator.getRoutesByAutnum(asn, ipv6_enabled=True)
            if ans is None:
                raise LookupError

            dbObj = et.fromstring(ans)
            asnObj = rpsl.ASNObject(asn)
            ap = parsers.ASNParser(asnObj, True)
            ap.extractRoutes(dbObj)
            return asnObj

        except LookupError:
            tools.w("No Object found for %s " % asn)
            return None

        except Exception as e:
            tools.w("Failed to resolve DB object %s. %s " % (asn, e))
            return None

    def resolveASSet(self, setname, depth):

        loop = True
        if depth == depth_limit:
            tools.w("Emergency exit. Too much recursion.")
            return
        depth += 1

        while loop:
            try:
                ans = self.communicator.getFilterSet("as-set", setname)
                if ans is None:
                    raise LookupError

                dbObj = et.fromstring(ans)
                setObj = rpsl.AsSetObject(setname)
                aspa = parsers.ASSetParser(setObj)

                """ First variable refers to AS-SETs that are included and need to be resolved (recursively).
                    Second variable refers to ASNs that are included and need to be resolved.
                """
                unresolved, new_ASNset = aspa.parseMembers(dbObj, self.ASNdir, self.asSetdir)
                s = '"'
                for i in range(0, depth):
                    s += "-"
                tools.d("%s>Found %s ASNs and %s AS-SETs in %s" % (s, len(new_ASNset), len(unresolved), setname))

                for a in new_ASNset:
                    if a not in self.ASNdir.asnObjDir.keys():
                        o = self.resolveASN(a)
                    if o is not None:
                        self.ASNdir.appendASNObj(o)

                if len(unresolved) is 0:
                    # Break recursion if no other AS-SETs are included
                    loop = False
                else:
                    for u in unresolved:
                        self.resolveASSet(u, depth)

            except LookupError:
                tools.w("No Object found for %s " % setname)
                break

            except Exception as e:
                tools.w("Failed to resolve DB object %s. %s " % (setname, e))
                break

    def resolveRSSet(self, rsname):

        loop = True
        while loop:
            try:
                dbObj = et.fromstring(self.communicator.getFilterSet("route-set", rsname))
                setObj = rpsl.RouteSetObject(rsname)
                rspa = parsers.RSSetParser(setObj, self.ipv6_enabled)
                unresolved = rspa.parseMembers(dbObj, self.RSSetDir)
                if len(unresolved) is 0:
                    loop = False
                else:
                    for u in unresolved:
                        self.resolveRSSet(u)

            except Exception as e:
                tools.w("Failed to fully resolve -> %s. %s" % (rsname, e))
                break

    def recogniseFilter(self, pf):
        for f in pf.expression.split():

            if f == "ANY":
                tools.d("WE ARE OPEN -> " + str(f))
                return 0

            elif rpsl.is_ASN(f):
                tools.d("It is an ASN -> " + str(f))
                obj = self.resolveASN(f)
                if obj is not None:
                    # Possibility to get a garbage AS-num is quite high
                    self.ASNdir.appendASNObj(obj)
                return 0

            elif rpsl.is_AS_set(f):
                tools.d("It is an AS-SET -> " + str(f))
                # if f == "AS-OTENET":
                #     pass
                self.resolveASSet(f, -1)
                return 0

            elif rpsl.is_rs_set(f):
                tools.d("It is an RS-SET -> " + str(f))
                self.resolveRSSet(f)
                return 0

            elif rpsl.is_fltr_set(f):
                tools.d("It is an FILTER-SET -> " + str(f))
                return 0

            else:
                tools.w("Can not expand subject:", str(f), 'in rule', f)
                return 2  # No analyser of factor for the subject means that the prefix should not appear
