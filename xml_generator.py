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
    new_import.set('from', asn.upper())

    if local_ip is not None:
        new_import.set('local-ip', local_ip)
    if remote_ip is not None:
        new_import.set('remote-ip', remote_ip)

    return new_import


def get_export_template(asn, local_ip, remote_ip):
    new_export = et.Element('announce')
    new_export.set('to', asn)

    if local_ip is not None:
        new_export.set('local-ip', local_ip)
    if remote_ip is not None:
        new_export.set('remote-ip', remote_ip)

    return new_export


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
    template_root = et.Element(autnum.upper())
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


def get_policy_template(autnum, ipv4, ipv6):
    template_root = et.Element('root')
    template_root.append(et.Comment('This is a resolved XML policy file for ' + autnum))

    # First place the route/route6 objects per AS
    et.SubElement(template_root, 'route-objects')

    # Then place the AS-Sets
    et.SubElement(template_root, 'as-sets')

    # Then place the RS-Sets
    et.SubElement(template_root, 'rs-sets')

    # That comes later
    policy_root = et.SubElement(template_root, 'policy')

    if ipv4:
        et.SubElement(policy_root, 'imports')
        et.SubElement(policy_root, 'exports')

    if ipv6:
        et.SubElement(policy_root, 'v6imports')
        et.SubElement(policy_root, 'v6exports')

    et.SubElement(policy_root, 'default')

    return template_root
