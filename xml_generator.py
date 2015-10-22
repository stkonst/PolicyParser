__author__ = 'stavros'
import xml.etree.ElementTree as et


def get_action_template(action_items):

    new_action = et.Element('actions')
    if action_items is None:
        return new_action

    if action_items is not None:
        for action in action_items:
            if len(action) > 1:
                seperated = action.split('=')
                new_action.set(seperated[0], seperated[1])

    return new_action


def get_filter_template(filter_items):
    filters_root = et.Element('filters')
    if filter_items is None:
        return filters_root

    for item in filter_items:
        if "ANY" != item:
            f = et.SubElement(filters_root, "filter")
            f.text = item

    return filters_root


def create_new_prefix(version, prefix, origin):

    new_prefix = et.Element("prefix")
    new_prefix.set("version", version)

    if origin is not None:
        new_prefix.set("origin", origin.upper())
    new_prefix.text = prefix

    return new_prefix


def create_new_member(ref_type, value, version):
    new_member = et.Element("member")
    if ref_type is not None:
        new_member.set("referenced-type", ref_type)

    if version is not None:
        new_member.set("ip-version", version)

    new_member.text = value
    return new_member


def get_route_object_template(autnum):
    template_root = et.Element("object")
    template_root.set("aut-num", autnum.upper())
    et.SubElement(template_root, "prefixes")

    return template_root


def get_as_set_template(as_set):
    template_root = et.Element("filter")
    template_root.set("name", as_set.upper())
    et.SubElement(template_root, "members")

    return template_root


def get_rs_set_template(rs_set):
    template_root = et.Element("filter")
    template_root.set("name", rs_set.upper())
    et.SubElement(template_root, "members")

    return template_root


def get_peer_template(autnum, ipv4, ipv6, local_ipv4, remote_ipv4, local_ipv6, remote_ipv6, ):
    template_root = et.Element('peer')
    template_root.set("aut-num", autnum)

    if local_ipv4 is not None:
        template_root.set('local-ipv4', local_ipv4)

    if remote_ipv4 is not None:
        template_root.set('remote-ipv4', remote_ipv4)

    if local_ipv6 is not None:
        template_root.set('local-ipv6', local_ipv6)

    if remote_ipv6 is not None:
        template_root.set('remote-ipv6', remote_ipv6)

    if ipv4:
        et.SubElement(template_root, 'imports')
        et.SubElement(template_root, 'exports')

    if ipv6:
        et.SubElement(template_root, 'v6imports')
        et.SubElement(template_root, 'v6exports')

    et.SubElement(template_root, 'default')
    et.SubElement(template_root, 'mp-default')

    return template_root


def get_policy_template(autnum):

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
