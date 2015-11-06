__author__ = 'stavros'
import xml.etree.ElementTree as et

import xmlGenerator as xmlgen
import communicator as fetcher
import libtools as tools


# class PolicyConverter:
#     def __init__(self, autnum, ipv4=True, ipv6=True):
#         self.xml_policy = None
#         self.autnum = autnum
#         self.ipv4_enabled = ipv4
#         self.ipv6_enabled = ipv6
#
#     def initXMLtemplate(self):
#         """ Initialise the xml template where it will be used to fill with policy values """
#         self.xml_policy = xmlgen.getPolicyTemplate(self.autnum)
#
#     def resolveAS_set(self, db_object, as_set_name):
#
#         as_set_template = xmlgen.getAS_setTemplate(as_set_name)
#         for elem in db_object.iterfind('./objects/object[@type="as-set"]/attributes/attribute'):
#             if elem.attrib.get("name") == "members":
#                 new_member = xmlgen.createNewMemberTemplate(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
#                                                       "ipv4")
#                 as_set_template.find('members').append(new_member)
#             elif elem.attrib.get("name") == "mp-members":
#                 new_member = xmlgen.createNewMemberTemplate(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
#                                                       "ipv6")
#                 as_set_template.find('members').append(new_member)
#
#         self.xml_policy.find('as-sets').append(as_set_template)
#
#     def resolveRS_set(self, db_object, rs_set_name):
#
#         rs_set_template = xmlgen.getRS_setTemplate(rs_set_name)
#         for elem in db_object.iterfind('./objects/object[@type="route-set"]/attributes/attribute'):
#             if elem.attrib.get("name") == "members":
#                 new_member = xmlgen.createNewMemberTemplate(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
#                                                       "ipv4")
#                 rs_set_template.find('members').append(new_member)
#             elif elem.attrib.get("name") == "mp-members":
#                 new_member = xmlgen.createNewMemberTemplate(elem.attrib.get("referenced-type"), elem.attrib.get("value"),
#                                                       "ipv6")
#                 rs_set_template.find('members').append(new_member)
#
#         self.xml_policy.find('rs-sets').append(rs_set_template)
#
#     def parseFilter(self, policy_filter):
#
#         if tools.check_autnum_validity(policy_filter):
#             db_reply = fetcher.getRoutesByAutnum(policy_filter)
#             if db_reply is None:
#                 return
#             self.xml_policy.find('./route-objects').append(self.extractRoutesFromSearch(et.fromstring(db_reply)))
#
#         elif tools.check_rs_set_validity(policy_filter):
#             db_reply = fetcher.getFilterSet("route-set", policy_filter)
#             if db_reply is None:
#                 return
#             self.resolveRS_set(et.fromstring(db_reply), policy_filter)
#
#         elif tools.check_rtr_set_validity(policy_filter):
#             # Need to resolve the RTR-SET
#             print "%s is a rtr-set" % policy_filter
#
#         elif tools.check_as_set_validity(policy_filter):
#             db_reply = fetcher.getFilterSet("as-set", policy_filter)
#             if db_reply is None:
#                 return
#             self.resolveAS_set(et.fromstring(db_reply), policy_filter)
#
#         else:
#             print "%s is something different" % policy_filter
#
#
#     def extractRPSLpolicy(self, autnum):
#
#         all_peers = dict()
#
#         db_reply = fetcher.getPolicyByAutnum(autnum)
#         if db_reply is None:
#             return all_peers
#
#         # et_object = et.fromstring(db_reply)
#         # for elem in et_object.iterfind('./objects/object[@type="aut-num"]/attributes/attribute'):
#         #
#         #     line_parsed = False
#         #     if self.ipv4_enabled:
#         #
#         #         if "import" == elem.attrib.get("name"):
#         #             self.parseImportValues_v4(elem.attrib.get("value"), all_peers)
#         #             line_parsed = True
#         #
#         #         elif "export" == elem.attrib.get("name"):
#         #             self.parseExportValues_v4(elem.attrib.get("value"), all_peers)
#         #             line_parsed = True
#         #
#         #     if not line_parsed and self.ipv6_enabled:
#         #
#         #         if "mp-import" == elem.attrib.get("name"):
#         #             self.parseImportValues_v6(elem.attrib.get("value"), all_peers)
#         #
#         #         elif "mp-export" == elem.attrib.get("name"):
#         #             self.parseExportValues_v6(elem.attrib.get("value"), all_peers)
#
#         return all_peers
