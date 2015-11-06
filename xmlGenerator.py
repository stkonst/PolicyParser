__author__ = 'stavros'
import xml.etree.ElementTree as et


class xmlGenerator:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.autnum = autnum
        self.xml_policy = self.getPolicyTemplate(self.autnum)  # Init XML Template
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6

    def getActionTemplate(self, action_items):
        new_action = et.Element('actions')
        if action_items is None:
            return new_action

        if action_items is not None:
            for action in action_items:
                if len(action) > 1:
                    seperated = action.lower().split('=')
                    new_action.set(seperated[0], seperated[1])

        return new_action

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
        new_prefix = et.Element("prefix")
        new_prefix.set("version", version)

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
        template_root = et.Element("object")
        template_root.set("aut-num", autnum.upper())
        et.SubElement(template_root, "prefixes")

        return template_root

    def getAS_setTemplate(self, as_set):
        template_root = et.Element("filter")
        template_root.set("name", as_set.upper())
        et.SubElement(template_root, "members")

        return template_root

    def getRS_setTemplate(self, rs_set):
        template_root = et.Element("filter")
        template_root.set("name", rs_set.upper())
        et.SubElement(template_root, "members")

        return template_root

    def getPeerTemplate(self, PeerAS):
        template_root = et.Element('peer')
        template_root.set("aut-num", PeerAS.origin)

        # TODO Find a more clever way to avoid all these if
        if PeerAS.localIPv4 is not None:
            template_root.set('local-ipv4', PeerAS.localIPv4)

        if PeerAS.remoteIPv4 is not None:
            template_root.set('remote-ipv4', PeerAS.remoteIPv4)

        if PeerAS.localIPv6 is not None:
            template_root.set('local-ipv6', PeerAS.localIPv6)

        if PeerAS.remoteIPv6 is not None:
            template_root.set('remote-ipv6', PeerAS.remoteIPv6)

        # et.SubElement(template_root, 'default')
        # et.SubElement(template_root, 'mp-default')

        return template_root

    def getPolicyTemplate(self, autnum):
        template_root = et.Element('root')
        template_root.append(et.Comment('This is a resolved XML policy file for ' + autnum))

        # First place the route/route6 objects per AS
        et.SubElement(template_root, 'route-objects')

        # Then place the AS-Sets
        et.SubElement(template_root, 'as-sets')

        # Then place the RS-Sets
        et.SubElement(template_root, 'rs-sets')

        # That comes later
        et.SubElement(template_root, 'peering-policy')

        return template_root

    def peerToXML(self, PeerAS):
        template_root = self.getPeerTemplate(PeerAS)

        if PeerAS.ipv4:
            im = et.SubElement(template_root, 'imports')
            im.append(self.getActionTemplate(PeerAS.v4imports.get('actions')))
            im.append(self.getFilterTemplate(PeerAS.v4imports.get('filters')))

            ex = et.SubElement(template_root, 'exports')
            ex.append(self.getActionTemplate(PeerAS.v4exports.get('actions')))
            ex.append(self.getFilterTemplate(PeerAS.v4exports.get('filters')))

        if PeerAS.ipv6:
            im6 = et.SubElement(template_root, 'mp-imports')
            im6.append(self.getActionTemplate(PeerAS.v6imports.get('actions')))
            im6.append(self.getFilterTemplate(PeerAS.v6imports.get('filters')))

            ex6 = et.SubElement(template_root, 'mp-exports')
            ex6.append(self.getActionTemplate(PeerAS.v6exports.get('actions')))
            ex6.append(self.getFilterTemplate(PeerAS.v6exports.get('filters')))

        return template_root

    def convertPeersToXML(self, PeerObjDir):
        pointer = self.xml_policy.find('peering-policy')
        for p, val in PeerObjDir.peerTable.iteritems():
            pointer.append(self.peerToXML(val))

    def __str__(self):
        return et.dump(self.xml_policy)
