__author__ = 'stavros'
import xml.etree.ElementTree as et


def get_action_filter_template(action_items, filter_items):
    new_action = et.Element('actions')
    if action_items is not None:
        for action in action_items:
            if len(action) > 1:
                seperated = action.split('=')
                new_action.set(seperated[0], seperated[1])

    for item in filter_items:
        if "ANY" != item:
            f = et.SubElement(new_action, "filter")
            f.text = item

    return new_action


def get_import_template(asn, local_ip, remote_ip):
    new_import = et.Element('accept')
    new_import.set('from', asn)

    if local_ip is not None:
        new_import.set('local-ip', local_ip)
    if remote_ip is not None:
        new_import.set('remote-ip', remote_ip)

    return new_import


def create_new_prefix(version, prefix, origin):
    new_prefix = et.Element("prefix")
    new_prefix.set("version", version)

    if origin is not None:
        new_prefix.set("origin", origin)
    new_prefix.text = prefix
    return new_prefix


def get_route_object_template(autnum):
    route_template = et.Element(autnum)
    et.SubElement(route_template, "prefixes")

    return route_template


def get_policy_template(autnum):
    template_root = et.Element('root')
    template_root.append(et.Comment('This is a resolved XML policy file for ' + autnum))

    # First place the route/route6 objects per AS
    et.SubElement(template_root, 'route-objects')
    # route_root.append(get_route_object_template(autnum))

    # Then place the AS-Sets
    et.SubElement(template_root, 'as-sets')

    #That comes later
    policy_root = et.SubElement(template_root, 'policy')
    et.SubElement(policy_root, 'imports')
    et.SubElement(policy_root, 'v6imports')
    et.SubElement(policy_root, 'exports')
    et.SubElement(policy_root, 'v6exports')
    et.SubElement(policy_root, 'default')

    return template_root