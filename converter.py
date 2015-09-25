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
        self.xml_policy = xmlgen.get_policy_template(self.autnum)
        # new_template[3][0].append(xmlgen.get_import_template(self.autnum, "", ""))
        # Alternative can be: imports_element = new_template.find('policy').find('imports')

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

    def extract_import_v4_ips(self, policy_object):
        local_IP = None
        remote_IP = None

        items = re.split('\sat\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv4(subset_before[len(subset_before) - 1]):
            remote_IP = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv4(subset_after[0]):
            local_IP = subset_after[0]

        return local_IP, remote_IP

    def extract_import_v6_ips(self, policy_object):
        local_IP = None
        remote_IP = None

        items = re.split('\sat\s', policy_object, re.I)
        subset_before = items[0].split()
        subset_after = items[1].split()

        if tools.is_valid_ipv6(subset_before[len(subset_before) - 1]):
            remote_IP = subset_before[len(subset_before) - 1]

        if tools.is_valid_ipv6(subset_after[0]):
            local_IP = subset_after[0]

        return local_IP, remote_IP

    def parse_ipv4_import_values(self, policy_object):

        action_items = None
        remote_IP = None
        local_IP = None

        peer_item = re.split('\s', policy_object)[1].strip()

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept\.*', policy_object, re.I)[1].split()

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_import_v4_ips(policy_object)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_import = xmlgen.get_import_template(peer_item, local_IP, remote_IP)
        new_import.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_import

    def parse_ipv6_import_values(self, policy_object):

        action_items = None
        remote_IP = None
        local_IP = None

        # print policy_object
        peer_item = re.search('(AS\d*\s)', re.split('from', policy_object, re.I)[1].strip(), re.I).group(1)

        # First step: retrieve the filter items (Mandatory and multiple)
        filter_items = re.split('\.*accept\.*', policy_object, re.I)[1].split()

        # Second step: Check if there are any IPs of routers inside (Optional)
        if re.search('\sat\s', policy_object, re.I):
            local_IP, remote_IP = self.extract_import_v6_ips(policy_object)

        # Before third step check if optional action(s) exist
        if "action" in policy_object:
            # Forth step: extract the actions separately (Optional and multiple)
            actions = re.search(r'action(.*)accept', policy_object, re.I).group(1)
            action_items = actions.split(";")

        new_import = xmlgen.get_import_template(peer_item, local_IP, remote_IP)
        new_import.append(xmlgen.get_action_filter_template(action_items, filter_items))
        return new_import

    def extract_rpsl_policy_(self, db_object):

        if self.ipv4_enabled:
            ipv4_import_pointer = self.xml_policy.find('policy/imports')
            ipv4_export = list()

        if self.ipv6_enabled:
            ipv6_import_pointer = self.xml_policy.find('policy/v6imports')
            ipv6_export = list()

        for elem in db_object.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):

            line_parsed = False
            if self.ipv4_enabled:
                if "import" == elem.attrib.get("name"):
                    ipv4_import_pointer.append(self.parse_ipv4_import_values(elem.attrib.get("value")))
                    line_parsed = True
                elif "export" == elem.attrib.get("name"):
                    ipv4_export.append(elem.attrib.get("value"))
                    line_parsed = True

            if self.ipv6_enabled and not line_parsed:
                if "mp-import" == elem.attrib.get("name"):
                    ipv6_import_pointer.append(self.parse_ipv6_import_values(elem.attrib.get("value")))
                elif "mp-export" == elem.attrib.get("name"):
                    ipv6_export.append(elem.attrib.get("value"))

                    # return , ipv4_export, ipv6_import, ipv6_export

    def get_routes_from_object(self, autnum):
        db_object = et.fromstring(fetcher.send_db_request(
            fetcher.search_url_builder(autnum, "origin", "route", "route6")))

        return self.extract_routes_from_search(db_object)
