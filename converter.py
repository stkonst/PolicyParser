__author__ = 'stavros'
import xml.etree.ElementTree as et
import re

import xml_generator as xmlgen
import communicator as fetcher
import libtools as tools


class PolicyConverter:
    def __init__(self, autnum, ipv4=True, ipv6=True):
        self.xml_policy = None
        self.autnum = autnum
        self.ipv4_enabled = ipv4
        self.ipv6_enabled = ipv6

    def init_xml_template(self):
        """ Initialise the xml template where it will be used to fill with policy values """
        self.xml_policy = xmlgen.get_policy_template(self.autnum, self.ipv4_enabled, self.ipv6_enabled)

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

    def extract_v4_ips_from_item(self, policy_object):

        local_IP = None
        remote_IP = None

        items = re.split('\sat|AT\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv4(subset_before[len(subset_before) - 1]):
            remote_IP = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv4(subset_after[0]):
            local_IP = subset_after[0]

        return local_IP, remote_IP

    def extract_v6_ips_from_item(self, policy_object):

        local_IP = None
        remote_IP = None

        items = re.split('\sat|AT\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv6(subset_before[len(subset_before) - 1]):
            remote_IP = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv6(subset_after[0]):
            local_IP = subset_after[0]

        return local_IP, remote_IP

    def parse_ipv4_import_values(self, policy_object, unknown_as, unknown_filters):

        action_items = None
        remote_IP = None
        local_IP = None

        peer_as = re.split('\s', policy_object)[1].strip()
        unknown_as.add(peer_as)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept|ACCEPT\.*', policy_object, re.I)[1].split()
        unknown_filters.update(set(filter_items))

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_v4_ips_from_item(policy_object)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_import = xmlgen.get_import_template(peer_as, local_IP, remote_IP)
        new_import.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_import

    def parse_ipv4_export_values(self, policy_object, unknown_as, unknown_filters):

        action_items = None
        remote_IP = None
        local_IP = None

        peer_as = re.split('\s', policy_object)[1].strip()
        unknown_as.add(peer_as)

        # First get the announce (filter) items
        filter_items = re.split('\.*announce|ANNOUNCE\.*', policy_object, re.I)[1].split()
        unknown_filters.update(set(filter_items))

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_v4_ips_from_item(policy_object)

        # Then let's receive the actions that need to be applied
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)announce', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_export = xmlgen.get_export_template(peer_as, local_IP, remote_IP)
        new_export.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_export

    def parse_ipv6_import_values(self, policy_object, unknown_as, unknown_filters):

        action_items = None
        remote_IP = None
        local_IP = None

        # Get the peer AS first
        peer_as = re.search('(AS\d*\s)', re.split('from|FROM', policy_object, re.I)[1].strip(), re.I).group(1)
        unknown_as.add(peer_as)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept|ACCEPT\.*', policy_object, re.I)[1].split()
        unknown_filters.update(set(filter_items))

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_v6_ips_from_item(policy_object)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_import = xmlgen.get_import_template(peer_as, local_IP, remote_IP)
        new_import.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_import

    def parse_ipv6_export_values(self, policy_object, unknown_as, unknown_filters):
        action_items = None
        remote_IP = None
        local_IP = None

        peer_as = re.search('(AS\d*\s)', re.split('to|TO', policy_object, re.I)[1].strip(), re.I).group(1)
        unknown_as.add(peer_as)

        # First get the announce (filter) items
        filter_items = re.split('\.*announce|ANNOUNCE\.*', policy_object, re.I)[1].split()
        unknown_filters.update(set(filter_items))

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_v6_ips_from_item(policy_object)

        # Then let's receive the actions that need to be applied
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)announce', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_export = xmlgen.get_export_template(peer_as, local_IP, remote_IP)
        new_export.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_export

    def extract_rpsl_policy(self, autnum):

        unknown_as = set()
        unknown_filters = set()

        db_reply = self.get_policy_by_autnum(autnum)
        if db_reply is None:
            return unknown_as, unknown_filters

        db_object = et.fromstring(db_reply)
        if self.ipv4_enabled:
            ipv4_import_pointer = self.xml_policy.find('policy/imports')
            ipv4_export_pointer = self.xml_policy.find('policy/exports')

        if self.ipv6_enabled:
            ipv6_import_pointer = self.xml_policy.find('policy/v6imports')
            ipv6_export_pointer = self.xml_policy.find('policy/v6exports')

        for elem in db_object.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):

            line_parsed = False
            if self.ipv4_enabled:

                if "import" == elem.attrib.get("name"):
                    ipv4_import_pointer.append(
                        self.parse_ipv4_import_values(elem.attrib.get("value"), unknown_as, unknown_filters))
                    line_parsed = True

                elif "export" == elem.attrib.get("name"):
                    ipv4_export_pointer.append(
                        self.parse_ipv4_export_values(elem.attrib.get("value"), unknown_as, unknown_filters))
                    line_parsed = True

            if not line_parsed and self.ipv6_enabled:

                if "mp-import" == elem.attrib.get("name"):
                    ipv6_import_pointer.append(
                        self.parse_ipv6_import_values(elem.attrib.get("value"), unknown_as, unknown_filters))

                elif "mp-export" == elem.attrib.get("name"):
                    ipv6_export_pointer.append(
                        self.parse_ipv6_export_values(elem.attrib.get("value"), unknown_as, unknown_filters))

        return unknown_as, unknown_filters

    def get_routes_from_object(self, autnum):

        db_reply = fetcher.send_db_request(fetcher.search_url_builder(autnum, "origin", "route", "route6"))
        if "No Objects found" in db_reply or "Illegal input" in db_reply:
            xml_error_answer = xmlgen.get_route_object_template(autnum)
            xml_error_answer.set("ERROR", db_reply)
            return xml_error_answer

        db_object = et.fromstring(db_reply.encode('utf-8').strip())
        if db_object.find('errormessages/errormessage[@severity="Error"]'):
            return xmlgen.get_route_object_template(autnum)

        return self.extract_routes_from_search(db_object)

    def get_policy_by_autnum(self, autnum):

        db_reply = fetcher.send_db_request(fetcher.locator_url_builder("aut-num", autnum))
        if "No Objects found" in db_reply or "Illegal input" in db_reply:
            return None
        return db_reply
