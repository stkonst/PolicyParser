__author__ = 'stavros'
import requests

import libtools


class Communicator:
    def __init__(self, db_url, source):
        self.db_url = db_url
        self.source = source

    def getPolicyByAutnum(self, autnum):
        db_reply = None
        try:
            db_reply = self.sendDbRequest(self.locatorURLbuilder("aut-num", autnum))
            libtools.d("Policy received for %s" % autnum)
        except:
            libtools.w("Failed to receive policy for %s" % autnum)
            pass

        return db_reply

    def getFilterSet(self, ftype, value):
        # Can make requests for as-set, route-set
        db_reply = None
        try:
            db_reply = self.sendDbRequest(self.locatorURLbuilder(ftype, value))
        except:
            libtools.w('Get Filter failed for %s' % value)
            pass
        return db_reply

    def getRoutesByAutnum(self, autnum, ipv6_enabled=False):

        db_reply = None
        if ipv6_enabled:
            url = self.searchURLbuilder(autnum, "origin", "route", "route6", flags=None)
        else:
            url = self.searchURLbuilder(autnum, "origin", "route")

        try:
            db_reply = self.sendDbRequest(url)
        except Exception as e:
            libtools.w('Get all routes failed for %s. %s' % (autnum, e))
            pass
        return db_reply

    def locatorURLbuilder(self, db_type, db_key):
        """
        Example url: http://rest.db.ripe.net/ripe/aut-num/AS199664
        """
        return self.db_url + "/%s/%s/%s" % (self.source, db_type, db_key)

    def searchURLbuilder(self, query_string, inverse_attribute, type_filter1, type_filter2=None, flags=None):
        """
        Example:
            http://rest.db.ripe.net/search.xml?query-string=as199664&type-filter=route6&inverse-attribute=origin
        """
        new_url = "/search.xml?query-string=%s" % query_string
        if inverse_attribute is not None:
            new_url += "&inverse-attribute=%s" % inverse_attribute
        if type_filter1 is not None:
            new_url += "&type-filter=%s" % type_filter1
        if type_filter2 is not None:
            new_url += "&type-filter=%s" % type_filter2
        if flags is not None:
            new_url += "&flags=%s" % flags

        return self.db_url + new_url

    def sendDbRequest(self, db_url):

        try:
            # headers = {'Content-Type': 'application/json'}
            headers = {'Accept': 'application/xml'}
            r = requests.get(db_url, headers=headers)
            if r.status_code == 200:
                return r.text.encode(encoding='utf-8')
            elif r.status_code == 400:
                raise Exception("Illegal input - incorrect value in one or more of the parameters")
            elif r.status_code == 404:
                raise Exception("No Objects found")
        except:
            # dunno, we got another type of Error
            raise
