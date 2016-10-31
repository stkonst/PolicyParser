import xml.etree.ElementTree as et
import datetime
from collections import deque


class XmlGenerator:
    def __init__(self, autnum):
        self.autnum = autnum
        self.name_prefix = "manta_"
        self.xml_policy = self.get_policy_template(self.autnum)  # Init XML Template

    def _get_action_template(self, policy_action_list):
        """Converts the policy actions of a peering point into XML format."""

        if policy_action_list.direction == "import":
            new_actions = et.Element('actions_in')
        elif policy_action_list.direction == "export":
            new_actions = et.Element('actions_out')

        while policy_action_list.data:
            i, ac = policy_action_list.data.popitem()
            if ac.rp_operator == "append":
                new_actions.set(ac.rp_attr.lower(),
                                "append({})".format(ac.rp_value))
            elif ac.rp_operator == "delete":
                new_actions.set(ac.rp_attr.lower(),
                                "delete({})".format(ac.rp_value))
            elif ac.rp_operator == "prepend":
                new_actions.set(ac.rp_attr.lower(),
                                "prepend({})".format(ac.rp_value))
            elif ac.rp_operator == "=":
                new_actions.set(ac.rp_attr.lower(), ac.rp_value)

        return new_actions

    def _get_filter_template(self, text):
        filters_root = et.Element('filters')
        if text is None:
            return filters_root

        f = et.SubElement(filters_root, "filter")
        f.text = text

        return filters_root

    def _create_new_prefix_template(self, version, prefix, origin):
        new_prefix = et.Element("prefix").set("version", version)

        if origin is not None:
            new_prefix.set("origin", origin.upper())
        new_prefix.text = prefix

        return new_prefix

    def get_policy_template(self, autnum):
        """Builds the basic high level structure of the XML document."""
        template_root = et.Element('root')

        template_root.append(et.Comment('This is a resolved XML policy file '
                                        'for {}'.format(autnum)))
        et.SubElement(template_root, 'datetime').text = str(datetime.datetime.now())

        et.SubElement(template_root, 'prefix-lists')

        et.SubElement(template_root, 'peering-filters')

        et.SubElement(template_root, 'peering-policy')

        return template_root

    def _filter_to_XML(self, peer_filter):
        fltr_root = et.Element('peering-filter',
                               attrib={"hash-value": peer_filter.hash_value,
                                       "afi": peer_filter.afi})
        et.SubElement(fltr_root, "expression").text = peer_filter.expression
        statement_root = et.SubElement(fltr_root, "statements")

        for i, t in enumerate(peer_filter.statements):
            if t.allow:
                st = et.SubElement(statement_root, 'statement',
                                   attrib={'order': str(i), 'type': 'accept'})
            else:
                st = et.SubElement(statement_root, 'statement',
                                   attrib={'order': str(i), 'type': 'deny'})

            for item in t.members:
                if item.category == "AS_PATH":
                    et.SubElement(st, 'as-path').text = str(item.data[1])
                elif item.category in ("AS", "AS_set", "rs_set"):
                    et.SubElement(st, 'prefix-list').text = self.name_prefix + str(item.data)
                elif item.category == "prefix_list":
                    for p in item.data:
                        et.SubElement(st, 'prefix-list').text = self.name_prefix + p

        return fltr_root

    def _AS_to_XML(self, AS_object, pl):
        """Converts a given AS number into a prefix list with ipv4/ipv6
        prefixes.
        """
        for r in AS_object.route_obj_dir.origin_table.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

        for r in AS_object.route_obj_dir.origin_table_v6.itervalues():
            et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route

    def _route_set_to_XML(self, route_set_object, route_set_object_dir, pl):
        """Traverses the tree created by the RSes. Ignores duplicate routes
        and avoids loops.
        """
        route_set_tree = deque([route_set_object.get_key()])
        traversed_route_sets = set()
        traversed_routes = set()

        while route_set_tree:
            current_set_name = route_set_tree.popleft()
            current_set = route_set_object_dir.data[current_set_name]
            for r in current_set.members.origin_table.itervalues():
                if r.route not in traversed_routes:
                    et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route
                    traversed_routes.add(r.route)

            for r in current_set.mp_members.origin_table_v6.itervalues():
                if r.route not in traversed_routes:
                    et.SubElement(pl, 'prefix', attrib={'type': r.ROUTE_ATTR}).text = r.route
                    traversed_routes.add(r.route)

            for child_set in current_set.RSes_dir:
                if child_set not in traversed_route_sets:
                    traversed_route_sets.add(child_set)
                    route_set_tree.extend(child_set)

    def _AS_set_to_XML(self, AS_set_object, AS_object_dir, AS_set_object_dir,
                       pl_root):
        """Traverses the tree created by the AS sets. Ignores duplicate ASes
        and avoids loops.
        """
        AS_set_tree = deque([AS_set_object.get_key()])
        traversed_AS_sets = set()
        traversed_ASes = set()

        while AS_set_tree:
            current_set_name = AS_set_tree.popleft()
            current_set = AS_set_object_dir.data[current_set_name]
            for child_AS in current_set.ASN_members:
                if child_AS not in traversed_ASes:
                    traversed_ASes.add(child_AS)
                    try:
                        self._AS_to_XML(AS_object_dir.data[child_AS], pl_root)
                    except KeyError:
                        pass

            for child_set in current_set.AS_set_members:
                if child_set not in traversed_AS_sets:
                    traversed_AS_sets.add(child_set)
                    AS_set_tree.extend(child_set)

    def _peering_point_to_XML(self, points_root, peering_point):
        if peering_point.get_key() is not "|":
            pp_root = et.Element('peering-point')

            p = et.SubElement(pp_root, "point",
                              attrib={"local-IP": peering_point.local_ip,
                                      "remote-IP": peering_point.remote_ip})
            p.append(self._get_action_template(peering_point.actions_in))
            p.append(self._get_action_template(peering_point.actions_out))

            points_root.append(pp_root)

        else:
            points_root.append(self._get_action_template(peering_point.actions_in))
            points_root.append(self._get_action_template(peering_point.actions_out))

    def peer_to_XML(self, peer_AS):
        template_root = et.Element('peer', attrib={"aut-num": peer_AS.origin})

        points = et.SubElement(template_root, 'peering-points')
        for pp in peer_AS.peering_points.itervalues():
            self._peering_point_to_XML(points, pp)

        im = et.SubElement(template_root, 'imports')
        ex = et.SubElement(template_root, 'exports')

        for f, v in peer_AS.filters.iteritems():
            if v == "import":
                im.append(self._get_filter_template(f))
            elif v == "export":
                ex.append(self._get_filter_template(f))

        im = et.SubElement(template_root, 'mp-imports')
        ex = et.SubElement(template_root, 'mp-exports')

        for f, v in peer_AS.mp_filters.iteritems():
            if v == "import":
                im.append(self._get_filter_template(f))
            elif v == "export":
                ex.append(self._get_filter_template(f))

        return template_root

    def convert_filters_to_XML(self, peer_filter_dir):
        for val in peer_filter_dir.filter_table.itervalues():
            self.xml_policy.find('peering-filters').append(self._filter_to_XML(val))

    def convert_peers_to_XML(self, peer_obj_dir):
        for val in peer_obj_dir.peer_table.itervalues():
            self.xml_policy.find('peering-policy').append(self.peer_to_XML(val))

    def convert_lists_to_XML(self, AS_list, AS_object_dir, RS_list,
                             route_set_object_dir, AS_set_list,
                             AS_set_object_dir):
        p = self.xml_policy.find('prefix-lists')

        for s in AS_set_list:
            pl = et.SubElement(p, 'prefix-list', attrib={'name': self.name_prefix + s})

            try:
                obj = AS_set_object_dir.data[s]
                self._AS_set_to_XML(obj, AS_object_dir, AS_set_object_dir, pl)
            except KeyError:
                pass

        for v in AS_list:
            pl = et.SubElement(p, 'prefix-list', attrib={'name': self.name_prefix + v})

            try:
                obj = AS_object_dir.data[v]
                self._AS_to_XML(obj, pl)
            except KeyError:
                pass

        for r in RS_list:
            pl = et.SubElement(p, 'prefix-list', attrib={'name': self.name_prefix + r})

            try:
                obj = route_set_object_dir.data[r]
                self._route_set_to_XML(obj, route_set_object_dir, pl)
            except KeyError:
                pass

    def __str__(self):
        return et.tostring(self.xml_policy, encoding='UTF-8')
