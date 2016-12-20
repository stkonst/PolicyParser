import datetime
from collections import deque

import yaml


class YamlGenerator:
    def __init__(self):
        self.name_prefix = "manta_"
        self.yaml_policy = {'datetime': str(datetime.datetime.now())}

    def print_policy(self):
        return yaml.dump(self.yaml_policy, default_flow_style=False, allow_unicode=True, indent=4)

    def _get_all_AS_routes(self, AS_object, routes4, routes6):
        """ Returns all the prefixes of a given AS object in two different sets (IPv4 and IPv6)
        """

        for r in AS_object.route_obj_dir.origin_table.itervalues():
            routes4.append(r.route)

        for r in AS_object.route_obj_dir.origin_table_v6.itervalues():
            routes6.append(r.route)

    def _convert_AS_to_dict(self, AS_object):
        """Converts a given AS number into a dictionary which includes all IPv4 and IPv6 addresses
       """

        routes4 = []
        routes6 = []

        self._get_all_AS_routes(AS_object, routes4, routes6)

        return {self.name_prefix + AS_object.origin: {'ipv4': routes4, 'ipv6': routes6}}

    def _convert_ASset_to_dict(self, AS_set_object, AS_object_dir, AS_set_object_dir):
        """Traverses the tree created by the AS sets. Ignores duplicate ASes
        and avoids loops.
        """
        AS_set_tree = deque([AS_set_object.get_key()])
        traversed_AS_sets = set()
        traversed_ASes = set()

        routes4 = []
        routes6 = []

        while AS_set_tree:
            current_set_name = AS_set_tree.popleft()
            current_set = AS_set_object_dir.data[current_set_name]
            for child_AS in current_set.ASN_members:
                if child_AS not in traversed_ASes:
                    traversed_ASes.add(child_AS)
                    try:
                        self._get_all_AS_routes(AS_object_dir.data[child_AS], routes4, routes6)
                    except KeyError:
                        pass

            for child_set in current_set.AS_set_members:
                if child_set not in traversed_AS_sets:
                    traversed_AS_sets.add(child_set)
                    AS_set_tree.append(child_set)

        return {'ipv4': routes4, 'ipv6': routes6}

    def _convert_RS_to_dict(self, route_set_object, route_set_object_dir):
        """Traverses the tree created by the RSes. Ignores duplicate routes
        and avoids loops.
        """
        route_set_tree = deque([route_set_object.get_key()])
        traversed_route_sets = set()
        traversed_routes = set()

        routes4 = []
        routes6 = []

        while route_set_tree:
            current_set_name = route_set_tree.popleft()
            current_set = route_set_object_dir.data[current_set_name]
            for r in current_set.members.origin_table.itervalues():
                if r.route not in traversed_routes:
                    routes4.append(r.route)
                    traversed_routes.add(r.route)

            for r in current_set.mp_members.origin_table_v6.itervalues():
                if r.route not in traversed_routes:
                    routes6.append(r.route)
                    traversed_routes.add(r.route)

            for child_set in current_set.RSes_dir:
                if child_set not in traversed_route_sets:
                    traversed_route_sets.add(child_set)
                    route_set_tree.append(child_set)

        return {'ipv4': routes4, 'ipv6': routes6}

    def _filter_to_dict(self, peer_filter):

        """
        Converts a peer filter that is applied in a peer of the peering policy into YAML format. The peer filter is
        type of accept or deny and includes the statements (AS-paths or prefix-lists) that need be accepted or denied.
        """

        statements = {}
        for i, t in enumerate(peer_filter.statements):

            statement = {}
            if t.allow:
                statement['type'] = 'accept'
            else:
                statement['type'] = 'deny'

            for item in t.members:
                if item.category == "AS_PATH":
                    statement['AS_PATH'] = item.data[1]
                elif item.category in ("AS", "AS_set", "rs_set"):
                    statement['prefix-list'] = self.name_prefix + str(item.data)
                elif item.category == "prefix_list":
                    statement['prefix-list'] = [self.name_prefix + p for p in item.data]

            statements[str(i)] = statement
        return {peer_filter.hash_value: {'afi': peer_filter.afi, 'expression': peer_filter.expression,
                                         'statements': statements}}

    def _peer_to_dict(self, peer_AS):

        """
        Converts a peer object that is found in the peering policy into YAML format. Currently only imports/exports
        are converted. TODO: extend the function to insert actions also.
        """

        imports = []
        exports = []

        for f, v in peer_AS.filters.iteritems():
            if v == "import":
                imports.append(f)

            elif v == "export":
                exports.append(f)

        mp_imports = []
        mp_exports = []

        for f, v in peer_AS.mp_filters.iteritems():
            if v == "import":
                mp_imports.append(f)

            elif v == "export":
                mp_exports.append(f)

        return {peer_AS.origin: {"filters": {"imports": imports, "exports": exports, "mp-imports": mp_imports,
                                             "mp-exports": mp_exports}}}

    def convert_lists_to_dict(self, AS_list, AS_object_dir, RS_list, route_set_object_dir, AS_set_list,
                              AS_set_object_dir):
        dic_objects = dict()
        for s in AS_set_list:
            try:
                obj = AS_set_object_dir.data[s]
                thing = self._convert_ASset_to_dict(obj, AS_object_dir, AS_set_object_dir)
                dic_objects[self.name_prefix + s] = thing
            except KeyError as e:
                print "{}:{}".format(e.__class__.__name__, e)
                pass

        for v in AS_list:
            try:
                obj = AS_object_dir.data[v]
                dic_objects.update(self._convert_AS_to_dict(obj))

            except KeyError:
                pass

        for r in RS_list:
            try:
                obj = route_set_object_dir.data[r]
                dic_objects[self.name_prefix + r] = self._convert_RS_to_dict(obj, route_set_object_dir)
            except KeyError:
                pass

        self.yaml_policy['prefix-lists'] = dic_objects

    def convert_filters_to_dict(self, peer_filter_dir):
        pfilters = {}
        for val in peer_filter_dir.filter_table.itervalues():
            pfilters.update(self._filter_to_dict(val))

        self.yaml_policy['peering-filters'] = pfilters

    def convert_peers_to_yaml(self, peer_obj_dir):
        peersdir = {}

        for val in peer_obj_dir.peer_table.itervalues():
            peersdir.update(self._peer_to_dict(val))
        self.yaml_policy['peering-policy'] = peersdir
