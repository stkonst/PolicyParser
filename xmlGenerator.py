__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
import xml.etree.ElementTree as et
import datetime


class xmlGenerator:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.autnum = autnum
        self.xml_policy = self.getPolicyTemplate(self.autnum)  # Init XML Template
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6

    def _getActionTemplate(self, PolicyActionList):

        if PolicyActionList.direction == "import":
            new_actions = et.Element('actions_in')
        elif PolicyActionList.direction == "export":
            new_actions = et.Element('actions_out')

        # TODO Insert order of applying actions
        while PolicyActionList.actionDir:
            i, ac = PolicyActionList.actionDir.popitem()
            if ac.rp_operator == ".=":
                new_actions.set(ac.rp_attr.lower(), "append(%s)" % ac.rp_value)
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
        template_root.append(et.Comment('Datetime of creation ( %s )' % datetime.datetime.now()))

        et.SubElement(template_root, 'peering-filters')

        et.SubElement(template_root, 'peering-policy')

        return template_root

    def _filterToXML(self, peerFilter):

        fltr_root = et.Element('peering-filter',
                               attrib={"type": str(peerFilter.type), "hash-value": peerFilter.hashValue})
        et.SubElement(fltr_root, "expression").text = peerFilter.expression
        ac = et.SubElement(fltr_root, "rules", attrib={"type": "accept"})
        re = et.SubElement(fltr_root, "rules", attrib={"type": "reject"})

        et.SubElement(ac, "prefix-list")
        et.SubElement(ac, "communities")
        et.SubElement(ac, "as-path")

        et.SubElement(re, "prefix-list")
        et.SubElement(re, "communities")
        et.SubElement(re, "as-path")

        return fltr_root

    def _peeringPointToXML(self, points_root, PeeringPoint):

        if PeeringPoint.getKey() is not "|":
            if PeeringPoint.mp:
                pp_root = et.Element('peering-point')
                pp_root.set("type", "IPv6")
            else:
                pp_root = et.Element('peering-point', attrib={"type": "IPv4"})

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
            # points.append(self._peeringPointToXML(pp))
            self._peeringPointToXML(points, pp)

        if self.ipv4_enabled:
            im = et.SubElement(template_root, 'imports')
            ex = et.SubElement(template_root, 'exports')
            for f, v in PeerAS.v4Filters.iteritems():
                if v[0] == "import":
                    im.append(self._getFilterTemplate(f))
                if v[0] == "export":
                    ex.append(self._getFilterTemplate(f))

        if self.ipv6_enabled:
            im = et.SubElement(template_root, 'mp-imports')
            ex = et.SubElement(template_root, 'mp-exports')
            for f, v in PeerAS.v4Filters.iteritems():
                if v[0] == "import":
                    im.append(self._getFilterTemplate(f))
                if v[0] == "export":
                    ex.append(self._getFilterTemplate(f))

        return template_root

    def convertFiltersToXML(self, peerFilterDir):
        for p, val in peerFilterDir.filterTable.iteritems():
            self.xml_policy.find('peering-filters').append(self._filterToXML(val))

    def convertPeersToXML(self, PeerObjDir):
        for p, val in PeerObjDir.peerTable.iteritems():
            self.xml_policy.find('peering-policy').append(self.peerToXML(val))

    def __str__(self):
        return et.tostring(self.xml_policy, encoding='UTF-8')
