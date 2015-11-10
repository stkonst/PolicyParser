__author__ = 'stavros'
import xml.etree.ElementTree as et


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

        # TODO Insert order of applying actions_in
        while PolicyActionList.actionDir:
            i, ac = PolicyActionList.actionDir.popitem()
            if ac.rp_operator == ".=":
                new_actions.set(ac.rp_attr.lower(), "append(%s)" % ac.rp_value)
            elif ac.rp_operator == "=":
                new_actions.set(ac.rp_attr.lower(), ac.rp_value)

        return new_actions

    def getFilterTemplate(self, filter_items):
        filters_root = et.Element('filters')
        if filter_items is None:
            return filters_root

        for item in filter_items:
            if "ANY" != item:
                f = et.SubElement(filters_root, "filter")
                f.text = item

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

        et.SubElement(template_root, 'route-objects')

        et.SubElement(template_root, 'as-sets')

        et.SubElement(template_root, 'rs-sets')

        et.SubElement(template_root, 'peering-policy')

        return template_root

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
            im.append(self.getFilterTemplate(PeerAS.v4Filters.get('imports')))
            ex = et.SubElement(template_root, 'exports')
            ex.append(self.getFilterTemplate(PeerAS.v4Filters.get('exports')))

        if self.ipv6_enabled:
            im = et.SubElement(template_root, 'mp-imports')
            im.append(self.getFilterTemplate(PeerAS.v6Filters.get('imports')))
            ex = et.SubElement(template_root, 'mp-exports')
            ex.append(self.getFilterTemplate(PeerAS.v6Filters.get('exports')))

        return template_root

    def convertPeersToXML(self, PeerObjDir):
        for p, val in PeerObjDir.peerTable.iteritems():
            self.xml_policy.find('peering-policy').append(self.peerToXML(val))

    def __str__(self):
        return et.tostring(self.xml_policy, encoding='UTF-8')
