__author__ = 'Stavros Konstantaras (stavros@nlnetlabs.nl)'
import xml.etree.ElementTree as et
import datetime

class xmlGenerator:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.autnum = autnum
        self.xml_policy = self.getPolicyTemplate(self.autnum)  # Init XML Template
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6

    def getActionTemplate(self, PolicyActionList):

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

    def getFilterTemplate(self, text):
        filters_root = et.Element('filters')
        if text is None:
            return filters_root

        f = et.SubElement(filters_root, "filter")
        f.text = text

        return filters_root

    def createNewPrefixTemplate(self, version, prefix, origin):
        new_prefix = et.Element("prefix").set("version", version)

        if origin is not None:
            new_prefix.set("origin", origin.upper())
        new_prefix.text = prefix

        return new_prefix

    def createNewMemberTemplate(self, ref_type, value, version):
        new_member = et.Element("member")
        if ref_type is not None:
            new_member.set("referenced-type", ref_type)

        if version is not None:
            new_member.set("ip-version", version)

        new_member.text = value
        return new_member

    def getRouteObjectTemplate(self, autnum):

        return et.Element("object").set("aut-num", autnum.upper()).SubElement("prefixes")

    def getAS_setTemplate(self, as_set):

        return et.Element("filter").set("name", as_set.upper()).SubElement("members")

    def getRS_setTemplate(self, rs_set):

        return et.Element("filter").set("name", rs_set.upper()).SubElement("members")

    def getPolicyTemplate(self, autnum):

        template_root = et.Element('root')
        template_root.append(et.Comment('This is a resolved XML policy file for ' + autnum))
        template_root.append(et.Comment('Datetime of creation ( %s )' % datetime.datetime.now()))

        et.SubElement(template_root, 'peering-filters')

        et.SubElement(template_root, 'peering-policy')

        return template_root

    def filterToXML(self, peerFilter):

        fltr_root = et.Element('peering-filter',
                               attrib={"type": str(peerFilter.type), "hash-value": peerFilter.hashValue,
                                       "afi": peerFilter.afi})
        et.SubElement(fltr_root, "expression").text = peerFilter.expression

        return fltr_root

    def peeringPointToXML(self, points_root, PeeringPoint):

        if PeeringPoint.getKey() is not "|":
            if PeeringPoint.mp:
                pp_root = et.Element('peering-point')
                pp_root.set("type", "IPv6")
            else:
                pp_root = et.Element('peering-point')
                pp_root.set("type", "IPv4")

            p = et.SubElement(pp_root, "point")
            p.set("local-IP", PeeringPoint.local_ip)
            p.set("remote-IP", PeeringPoint.remote_ip)
            p.append(self.getActionTemplate(PeeringPoint.actions_in))
            p.append(self.getActionTemplate(PeeringPoint.actions_out))

            points_root.append(pp_root)

        else:
            points_root.append(self.getActionTemplate(PeeringPoint.actions_in))
            points_root.append(self.getActionTemplate(PeeringPoint.actions_out))

    def peerToXML(self, PeerAS):

        template_root = et.Element('peer')
        template_root.set("aut-num", PeerAS.origin)

        points = et.SubElement(template_root, 'peering-points')
        for pp in PeerAS.peeringPoints.itervalues():
            # points.append(self.peeringPointToXML(pp))
            self.peeringPointToXML(points, pp)

        if self.ipv4_enabled:
            im = et.SubElement(template_root, 'imports')
            ex = et.SubElement(template_root, 'exports')
            for f, v in PeerAS.v4Filters.iteritems():
                if v[0] == "import":
                    im.append(self.getFilterTemplate(f))
                if v[0] == "export":
                    ex.append(self.getFilterTemplate(f))

        if self.ipv6_enabled:
            im = et.SubElement(template_root, 'mp-imports')
            ex = et.SubElement(template_root, 'mp-exports')
            for f, v in PeerAS.v4Filters.iteritems():
                if v[0] == "import":
                    im.append(self.getFilterTemplate(f))
                if v[0] == "export":
                    ex.append(self.getFilterTemplate(f))

        return template_root

    def convertFiltersToXML(self, peerFilterDir):
        for p, val in peerFilterDir.filterTable.iteritems():
            self.xml_policy.find('peering-filters').append(self.filterToXML(val))

    def convertPeersToXML(self, PeerObjDir):
        for p, val in PeerObjDir.peerTable.iteritems():
            self.xml_policy.find('peering-policy').append(self.peerToXML(val))

    def __str__(self):
        return et.tostring(self.xml_policy, encoding='UTF-8')
