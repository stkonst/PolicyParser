__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
import xml.etree.ElementTree as et
import datetime


class xmlGenerator:
    def __init__(self, autnum):
        self.autnum = autnum
        self.xml_policy = self.getPolicyTemplate(self.autnum)  # Init XML Template
        # self.ipv6_enabled = ipv6

    def _getActionTemplate(self, PolicyActionList):

        if PolicyActionList.direction == "import":
            new_actions = et.Element('actions_in')
        elif PolicyActionList.direction == "export":
            new_actions = et.Element('actions_out')

        while PolicyActionList.actionDir:
            i, ac = PolicyActionList.actionDir.popitem()
            if ac.rp_operator == "append":
                new_actions.set(ac.rp_attr.lower(), "append(%s)" % ac.rp_value)
            elif ac.rp_operator == "delete":
                new_actions.set(ac.rp_attr.lower(), "delete(%s)" % ac.rp_value)
            elif ac.rp_operator == "prepend":
                new_actions.set(ac.rp_attr.lower(), "prepend(%s)" % ac.rp_value)
            elif ac.rp_operator == "=":
                new_actions.set(ac.rp_attr.lower(), ac.rp_value)

        return new_actions

    def _getFilterTemplate(self, text):
        filters_root = et.Element('filters')
        if text is None:
            return filters_root

        f = et.SubElement(filters_root, "filter")
        f.text = text

        return filters_root

    def _createNewPrefixTemplate(self, version, prefix, origin):
        new_prefix = et.Element("prefix").set("version", version)

        if origin is not None:
            new_prefix.set("origin", origin.upper())
        new_prefix.text = prefix

        return new_prefix

    def getPolicyTemplate(self, autnum):

        template_root = et.Element('root')

        template_root.append(et.Comment('This is a resolved XML policy file for ' + autnum))
        et.SubElement(template_root, 'datetime').text = str(datetime.datetime.now())

        et.SubElement(template_root, 'prefix-lists')

        et.SubElement(template_root, 'peering-filters')

        et.SubElement(template_root, 'peering-policy')

        return template_root

    def _filterToXML(self, peerFilter):

        fltr_root = et.Element('peering-filter', attrib={"hash-value": peerFilter.hashValue, "afi": peerFilter.afi})
        et.SubElement(fltr_root, "expression").text = peerFilter.expression
        statement_root = et.SubElement(fltr_root, "statements")

        for i, t in enumerate(peerFilter.statements):
            if t.allow:
                st = et.SubElement(statement_root, 'statement', attrib={'order': str(i), 'type': 'accept'})
            else:
                st = et.SubElement(statement_root, 'statement', attrib={'order': str(i), 'type': 'deny'})

            for item in t.members:
                if item.category == "AS_PATH":
                    et.SubElement(st, 'as-path').text = str(item.data[1])
                elif item.category in ("AS", "AS_set", "rs_set"):
                    et.SubElement(st, 'prefix-list').text = str(item.data)
                elif item.category == "prefix_list":
                    for p in item.data:
                        et.SubElement(st, 'prefix-list').text = p

        return fltr_root

    def _AStoXML(self, ASNObject, pl):

        for r in ASNObject.routeObjDir.originTable.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

        for r in ASNObject.routeObjDir.originTableV6.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

    def _RouteSetToXML(self, RouteSetObject, RouteSetObjectdir, pl):

        for r in RouteSetObject.members.originTable.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

        for r in RouteSetObject.mp_members.originTableV6.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

        for t in RouteSetObject.RSSetsDir:
            self._RouteSetToXML(RouteSetObjectdir.RouteSetObjDir[t], RouteSetObjectdir, pl)

    def _ASSETtoXML(self, AsSetObject, ASNObjectDir, AsSetObjectDir, pl_root):

        for m in AsSetObject.ASNmembers:
            try:
                self._AStoXML(ASNObjectDir.asnObjDir[m], pl_root)
            except KeyError:
                pass

        for t in AsSetObject.ASSetmember:
            self._ASSETtoXML(AsSetObjectDir.asSetObjDir[t], ASNObjectDir, AsSetObjectDir, pl_root)

    def _peeringPointToXML(self, points_root, PeeringPoint):

        if PeeringPoint.getKey() is not "|":
            pp_root = et.Element('peering-point')

            p = et.SubElement(pp_root, "point",
                              attrib={"local-IP": PeeringPoint.local_ip, "remote-IP": PeeringPoint.remote_ip})
            p.append(self._getActionTemplate(PeeringPoint.actions_in))
            p.append(self._getActionTemplate(PeeringPoint.actions_out))

            points_root.append(pp_root)

        else:
            points_root.append(self._getActionTemplate(PeeringPoint.actions_in))
            points_root.append(self._getActionTemplate(PeeringPoint.actions_out))

    def peerToXML(self, PeerAS):

        template_root = et.Element('peer', attrib={"aut-num": PeerAS.origin})

        points = et.SubElement(template_root, 'peering-points')
        for pp in PeerAS.peeringPoints.itervalues():
            self._peeringPointToXML(points, pp)

        im = et.SubElement(template_root, 'imports')
        ex = et.SubElement(template_root, 'exports')

        for f, v in PeerAS.filters.iteritems():
            if v == "import":
                im.append(self._getFilterTemplate(f))
            if v == "export":
                ex.append(self._getFilterTemplate(f))

        im = et.SubElement(template_root, 'mp-imports')
        ex = et.SubElement(template_root, 'mp-exports')

        for f, v in PeerAS.mp_filters.iteritems():
            if v == "import":
                im.append(self._getFilterTemplate(f))
            if v == "export":
                ex.append(self._getFilterTemplate(f))

        return template_root

    def convertFiltersToXML(self, peerFilterDir):
        for p, val in peerFilterDir.filterTable.iteritems():
            self.xml_policy.find('peering-filters').append(self._filterToXML(val))

    def convertPeersToXML(self, PeerObjDir):
        for p, val in PeerObjDir.peerTable.iteritems():
            self.xml_policy.find('peering-policy').append(self.peerToXML(val))

    def convertListsToXML(self, ASNList, ASNObjectDir, RSSetList, RouteSetObjectdir, ASSetList, AsSetObjectDir):

        p = self.xml_policy.find('prefix-lists')
        for s in ASSetList:
            try:
                obj = AsSetObjectDir.asSetObjDir[s]
                pl = et.SubElement(p, 'prefix-list', attrib={'name': obj.getKey()})
                self._ASSETtoXML(obj, ASNObjectDir, AsSetObjectDir, pl)
            except KeyError:
                pass

        for v in ASNList:
            try:
                obj = ASNObjectDir.asnObjDir[v]
                pl = et.SubElement(p, 'prefix-list', attrib={'name': obj.origin})
                self._AStoXML(obj, pl)

            except KeyError:
                pass

        for v in RSSetList:
            try:
                obj = RouteSetObjectdir.RouteSetObjDir[v]
                pl = et.SubElement(p, 'prefix-list', attrib={'name': obj.getKey()})
                self._RouteSetToXML(obj, RouteSetObjectdir, pl)
            except KeyError:
                pass

    def __str__(self):
        return et.tostring(self.xml_policy, encoding='UTF-8')
