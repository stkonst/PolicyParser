__author__ = 'stavros'
import xml.etree.ElementTree as et
import re

import xml_generator as xmlgen
import communicator as fetcher
import PeerAS as peer
import libtools as tools


class PolicyConverter:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.xml_policy = None
        self.autnum = autnum
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6

    def init_xml_template(self):
        """ Initialise the xml template where it will be used to fill with policy values """
        self.xml_policy = xmlgen.get_policy_template(self.autnum)

    def extract_routes_from_search(self, db_object):

        current_as_number = db_object.find('./parameters/query-strings/query-string').attrib.get("value")
        xml_routes = xmlgen.get_route_object_template(current_as_number)

        if self.ipv4_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route"]/primary-key'):
                new_prefix = None
                new_origin = None
                for subelem in elem.iterfind('./attribute[@name="route"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None and new_origin is not None:
                    new_entry = xmlgen.create_new_prefix("ipv4", new_prefix, new_origin)
                    xml_routes[0].append(new_entry)

        if self.ipv6_enabled:
            for elem in db_object.iterfind('./objects/object[@type="route6"]/primary-key'):
                new_prefix = None
                new_origin = None
                for subelem in elem.iterfind('./attribute[@name="route6"]'):
                    new_prefix = subelem.attrib.get("value")
                for subelem in elem.iterfind('./attribute[@name="origin"]'):
                    new_origin = subelem.attrib.get("value")
                if new_prefix is not None and new_origin is not None:
                    new_entry = xmlgen.create_new_prefix("ipv6", new_prefix, new_origin)
                    xml_routes[0].append(new_entry)
        return xml_routes

    def extract_v4_ips_from_item(self, policy_object, peer):

        items = re.split('\sat|AT\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv4(subset_before[len(subset_before) - 1]):
            peer.remote_ipv4 = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv4(subset_after[0]):
            peer.local_ipv4 = subset_after[0]

    def extract_v6_ips_from_item(self, policy_object, peer):

        items = re.split('\sat|AT\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv6(subset_before[len(subset_before) - 1]):
            peer.remote_ipv6 = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv6(subset_after[0]):
            peer.local_ipv6 = subset_after[0]

    def parse_ipv4_import_values(self, policy_object, all_peers):

        autnum = re.split('\s', policy_object)[1].strip().upper()

        if autnum not in all_peers:
            new_peer = peer.PeerAS(autnum, "", self.ipv4_enabled, self.ipv6_enabled)
            all_peers[autnum] = new_peer

        peer_as = all_peers.get(autnum)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept|ACCEPT\.*', policy_object, re.I)[1].split()
        peer_as.append_v4import_filters(filter_items)

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            self.extract_v4_ips_from_item(policy_object, peer_as)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            peer_as.append_v4import_actions(actions.split(";"))

    def parse_ipv4_export_values(self, policy_object, all_peers):

        autnum = re.split('\s', policy_object)[1].strip().upper()

        if autnum not in all_peers:
            new_peer = peer.PeerAS(autnum, "", self.ipv4_enabled, self.ipv6_enabled)
            all_peers[autnum] = new_peer

        peer_as = all_peers.get(autnum)

        # First get the announce (filter) items
        filter_items = re.split('\.*announce|ANNOUNCE\.*', policy_object, re.I)[1].split()
        peer_as.append_v4export_filters(filter_items)

        # Then let's receive the actions that need to be applied
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)announce', policy_object, re.I).group(1)
            peer_as.append_v4export_actions(actions.split(";"))

    def parse_ipv6_import_values(self, policy_object, all_peers):

        # Get the peer AS first
        autnum = re.search('(AS\d*\s)', re.split('from|FROM', policy_object, re.I)[1].strip(), re.I).group(
            1).strip().upper()

        if autnum not in all_peers:
            new_peer = peer.PeerAS(autnum, "", self.ipv4_enabled, self.ipv6_enabled)
            all_peers[autnum] = new_peer

        peer_as = all_peers.get(autnum)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept|ACCEPT\.*', policy_object, re.I)[1].split()
        peer_as.append_v6import_filters(filter_items)

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            self.extract_v6_ips_from_item(policy_object, peer_as)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            peer_as.append_v6import_actions(actions.split(";"))

    def parse_ipv6_export_values(self, policy_object, all_peers):

        autnum = re.search('(AS\d*\s)', re.split('to|TO', policy_object, re.I)[1].strip(), re.I).group(
            1).strip().upper()

        if autnum not in all_peers:
            new_peer = peer.PeerAS(autnum, "", self.ipv4_enabled, self.ipv6_enabled)
            all_peers[autnum] = new_peer

        peer_as = all_peers.get(autnum)

        # First get the announce (filter) items
        filter_items = re.split('\.*announce|ANNOUNCE\.*', policy_object, re.I)[1].split()
        peer_as.append_v6export_filters(filter_items)

        # Then let's receive the actions that need to be applied
        if "action" in policy_object:
            actions = re.search(r'action(.*)announce', policy_object, re.I).group(1)
            peer_as.append_v6export_actions(actions.split(";"))

    def resolve_as_set(self, db_object, as_set_name):

        as_set_template = xmlgen.get_as_set_template(as_set_name)
        for elem in db_object.iterfind('./objects/object[@type="as-set"]/attributes/attribute'):
            if elem.attrib.get("name") == "members":
                new_member = xmlgen.create_new_member(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
                                                      "ipv4")
                as_set_template.find('members').append(new_member)
            elif elem.attrib.get("name") == "mp-members":
                new_member = xmlgen.create_new_member(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
                                                      "ipv6")
                as_set_template.find('members').append(new_member)

        self.xml_policy.find('as-sets').append(as_set_template)

    def resolve_rs_set(self, db_object, rs_set_name):

        rs_set_template = xmlgen.get_rs_set_template(rs_set_name)
        for elem in db_object.iterfind('./objects/object[@type="route-set"]/attributes/attribute'):
            if elem.attrib.get("name") == "members":
                new_member = xmlgen.create_new_member(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
                                                      "ipv4")
                rs_set_template.find('members').append(new_member)
            elif elem.attrib.get("name") == "mp-members":
                new_member = xmlgen.create_new_member(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
                                                      "ipv6")
                rs_set_template.find('members').append(new_member)

        self.xml_policy.find('rs-sets').append(rs_set_template)

    def parse_filter(self, policy_filter):

        if tools.check_autnum_validity(policy_filter):
            db_reply = fetcher.get_routes_by_autnum(policy_filter)
            if db_reply is None:
                return
            self.xml_policy.find('./route-objects').append(self.extract_routes_from_search(et.fromstring(db_reply)))

        elif tools.check_rs_set_validity(policy_filter):
            db_reply = fetcher.get_filter_set("route-set", policy_filter)
            if db_reply is None:
                return
            self.resolve_rs_set(et.fromstring(db_reply), policy_filter)

        elif tools.check_rtr_set_validity(policy_filter):
            # Need to resolve the RTR-SET
            print "%s is a rtr-set" % policy_filter

        elif tools.check_as_set_validity(policy_filter):
            db_reply = fetcher.get_filter_set("as-set", policy_filter)
            if db_reply is None:
                return
            self.resolve_as_set(et.fromstring(db_reply), policy_filter)

        else:
            print "%s is something different" % policy_filter

    def convert_peers_toxml(self, allpeers):

        pointer = self.xml_policy.find('peering-policy')
        for p, val in allpeers.iteritems():
            pointer.append(val.toXML)

    def extract_rpsl_policy(self, autnum):

        all_peers = dict()

        db_reply = fetcher.get_policy_by_autnum(autnum)
        if db_reply is None:
            return all_peers

        et_object = et.fromstring(db_reply)
        for elem in et_object.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):

            line_parsed = False
            if self.ipv4_enabled:

                if "import" == elem.attrib.get("name"):
                    self.parse_ipv4_import_values(elem.attrib.get("value"), all_peers)
                    line_parsed = True

                elif "export" == elem.attrib.get("name"):
                    self.parse_ipv4_export_values(elem.attrib.get("value"), all_peers)
                    line_parsed = True

            if not line_parsed and self.ipv6_enabled:

                if "mp-import" == elem.attrib.get("name"):
                    self.parse_ipv6_import_values(elem.attrib.get("value"), all_peers)

                elif "mp-export" == elem.attrib.get("name"):
                    self.parse_ipv6_export_values(elem.attrib.get("value"), all_peers)

        return all_peers
