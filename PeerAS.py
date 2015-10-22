__author__ = 'stavros'
import xml_generator as xmlgen


class PeerAS:
    def __init__(self, autnum, asname, ipv4, ipv6):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.autnum = autnum
        self.asname = asname
        self.local_ipv4 = None
        self.remote_ipv4 = None
        self.local_ipv6 = None
        self.remote_ipv6 = None
        self.v4imports = {'filters': set(), 'actions': list()}
        self.v4exports = {'filters': set(), 'actions': list()}
        self.v6imports = {'filters': set(), 'actions': list()}
        self.v6exports = {'filters': set(), 'actions': list()}

    def update_peer_v4ips(self, local, remote):
        self.local_ipv4 = local
        self.remote_ipv4 = remote

    def update_peer_v6ips(self, local, remote):
        self.local_ipv6 = local
        self.remote_ipv6 = remote

    def append_v4import_actions(self, actions):
        if actions is not None:
            self.v4imports['actions'] = list(actions)

    def append_v4import_filters(self, filters):
        if filters is not None:
            self.v4imports['filters'] = set(filters)

    def append_v4export_actions(self, actions):
        if actions is not None:
            self.v4exports['actions'] = list(actions)

    def append_v4export_filters(self, filters):
        if filters is not None:
            self.v4exports['filters'] = set(filters)

    def append_v6import_actions(self, actions):
        if actions is not None:
            self.v6imports['actions'] = list(actions)

    def append_v6import_filters(self, filters):
        if filters is not None:
            self.v6imports['filters'] = set(filters)

    def append_v6export_actions(self, actions):
        if actions is not None:
            self.v6exports['actions'] = list(actions)

    def append_v6export_filters(self, filters):
        if filters is not None:
            self.v6exports['filters'] = set(filters)

    def get_all_filters(self):

        filter_set = set()
        if self.ipv4:
            filter_set.update(self.v4imports.get('filters'))
            filter_set.update(self.v4exports.get('filters'))
        if self.ipv6:
            filter_set.update(self.v6imports.get('filters'))
            filter_set.update(self.v6exports.get('filters'))

        return filter_set

    @property
    def toXML(self):

        template = xmlgen.get_peer_template(self.autnum, self.ipv4, self.ipv6, self.local_ipv4, self.remote_ipv4,
                                            self.local_ipv6, self.remote_ipv6)

        pointer = template.find('imports')
        pointer.append(xmlgen.get_action_template(self.v4imports.get('actions')))
        pointer.append(xmlgen.get_filter_template(self.v4imports.get('filters')))

        pointer = template.find('exports')
        pointer.append(xmlgen.get_action_template(self.v4exports.get('actions')))
        pointer.append(xmlgen.get_filter_template(self.v4exports.get('filters')))

        pointer = template.find('v6imports')
        pointer.append(xmlgen.get_action_template(self.v6imports.get('actions')))
        pointer.append(xmlgen.get_filter_template(self.v6imports.get('filters')))

        pointer = template.find('v6exports')
        pointer.append(xmlgen.get_action_template(self.v6exports.get('actions')))
        pointer.append(xmlgen.get_filter_template(self.v6exports.get('filters')))

        return template
