__author__ = 'stavros'
import requests

ripe_db_url = "https://rest.db.ripe.net"
default_db_source = "ripe"


def get_policy_by_autnum(autnum):
    db_reply = send_db_request(locator_url_builder("aut-num", autnum))
    if "No Objects found" in db_reply or "Illegal input" in db_reply:
        return None
    return db_reply


def get_filter_set(ftype, value):
    # Can make requests for as-set, route-set
    db_reply = send_db_request(locator_url_builder(ftype, value))
    if "No Objects found" in db_reply or "Illegal input" in db_reply:
        return None
    return db_reply


def get_routes_by_autnum(autnum):
    db_reply = send_db_request(search_url_builder(autnum, "origin", "route", "route6"))
    if "No Objects found" in db_reply or "Illegal input" in db_reply:
        return None

    return db_reply


def locator_url_builder(db_type, db_key, db_source=default_db_source):
    """http://rest.db.ripe.net/ripe/aut-num/AS199664"""
    new_url = "/%s/%s/%s" % (db_source, db_type, db_key)
    # new_url = "search.xml?query-string=%s" % db_key
    return ripe_db_url + new_url


def search_url_builder(query_string, inverse_attribute, type_filter1, type_filter2=None, flags=None):
    """Example:
        http://rest.db.ripe.net/search.xml?query-string=as199664&type-filter=route6&inverse-attribute=origin"""
    new_url = "/search.xml?query-string=%s" % query_string
    if inverse_attribute is not None:
        new_url += "&inverse-attribute=%s" % inverse_attribute
    if type_filter1 is not None:
        new_url += "&type-filter=%s" % type_filter1
    if type_filter2 is not None:
        new_url += "&type-filter=%s" % type_filter2
    if flags is not None:
        new_url += "&flags=%s" % flags

    return ripe_db_url + new_url


def send_db_request(dburl):
    db_reply = None
    try:
        # headers = {'Content-Type': 'application/json'}
        headers = {'Accept': 'application/xml'}
        r = requests.get(dburl, headers=headers)
        if r.status_code == 200:
            db_reply = r.text
        elif r.status_code == 400:
            db_reply = "Illegal input - incorrect value in one or more of the parameters"
        elif r.status_code == 404:
            db_reply = "No Objects found"
    except:
        pass

    return db_reply
