import logging

import requests

import errors
import rest_cache


class Communicator():
    ripe_db_url = "http://rest.db.ripe.net"
    default_db_source = "ripe"
    alternative_db_sources = ("RADB-GRS", "APNIC-GRS", "ARIN-GRS",
                              "LACNIC-GRS", "AFRINIC-GRS", "JPIRR-GRS")

    policy_keyword = 'policy'
    filterset_keyword = 'filterset'
    route_keyword = 'route'

    CACHING_ROOT_FOLDER = "~/.libParser/cache/"
    EXPIRE_TIMEOUT_AFTER = 86400

    def __init__(self, db_url=ripe_db_url, source=default_db_source,
                 alternatives=alternative_db_sources):
        def _get_alternatives(alternatives):
            s = []
            for i in alternatives:
                s.append("&source={}".format(i))
            return ''.join(s)

        self.db_url = db_url
        self.source = source
        self.other_sources = _get_alternatives(alternatives)
        self.session = requests.Session()
        self.session.headers = {'Accept': 'application/xml'}
        self.flags = set()
        self.flags.add('no-referenced')
        self.cache = rest_cache.RestCache(self.EXPIRE_TIMEOUT_AFTER, self.CACHING_ROOT_FOLDER)

        # (TCP keep-alive) Used when we have a not-yet-known closed session.
        # The server closes the connection, but we already have a request in
        # the wire. This results in requests.ConnectionError by the server. By
        # retrying we eventually open another connection.
        self.max_retries = 3

    def get_policy_by_autnum(self, autnum):
        db_reply = None
        url = self._search_URL_builder(autnum, None, (), self.flags)
        _cached_reply = self.cache.get_or(url, self.policy_keyword)
        if _cached_reply != "":
            db_reply = _cached_reply
            logging.debug('Policy for {} found in cache'.format(autnum))
        else:
            try:
                db_reply = self._send_DB_request(url)
                logging.debug("Policy received for {}".format(autnum))
                self.cache.update(url, db_reply, self.policy_keyword)
            except errors.RIPEDBError:
                logging.error("Failed to receive policy for "
                              "{} due to RIPE DB error.".format(autnum))
            except errors.SendRequestError as e:
                logging.error('Get policy failed. {}'.format(e))

        return db_reply

    def get_filter_set(self, value):
        """Makes requests for as-set, route-set."""
        db_reply = None
        url = self._search_URL_builder(value, None, (), self.flags)
        _cached_reply = self.cache.get_or(url, self.filterset_keyword)
        if _cached_reply != "":
            db_reply = _cached_reply
            logging.debug('Filter set {} found in cache'.format(value))
        else:
            try:
                db_reply = self._send_DB_request(url)
                self.cache.update(url, db_reply, self.filterset_keyword)
            except errors.RIPEDBError:
                logging.error('Get Filter failed for '
                              '{} due to RIPE DB error.'.format(value))
            except errors.SendRequestError as e:
                logging.error('Get all routes failed for {}. {}'.format(value, e))

        return db_reply

    def get_routes_by_autnum(self, autnum, ipv6_enabled=False):
        """Requests all the route[6] objects for a given AS number."""
        db_reply = None
        type_filter = ['route']
        if ipv6_enabled:
            type_filter.append('route6')

        url = self._search_URL_builder(autnum, 'origin', type_filter, self.flags)

        _cached_reply = self.cache.get_or(url, self.route_keyword)
        if _cached_reply != "":
            db_reply = _cached_reply
            logging.debug('Routes originated by {} found in cache'.format(autnum))
        else:
            try:
                db_reply = self._send_DB_request(url)
                self.cache.update(url, db_reply, self.route_keyword)
            except errors.RIPEDBError:
                logging.error('Get all routes failed for '
                              '{} due to RIPE DB error'.format(autnum))
            except errors.SendRequestError as e:
                logging.error('Get all routes failed for {}. {}'.format(autnum, e))

        return db_reply

    def _search_URL_builder(self, query_string, inverse_attribute,
                            type_filters, flags):
        """Builds the url that is required by the search service of the RIPE API.
        Example:
        http://rest.db.ripe.net/search.xml?query-string=as199664&type-filter=route6&inverse-attribute=origin
        """

        new_url = ["/search.xml?"
                   "query-string={}&source={}".format(query_string,
                                                      self.source)]
        new_url.append(self.other_sources)

        if inverse_attribute is not None:
            new_url.append("&inverse-attribute={}".format(inverse_attribute))

        for f in type_filters:
            new_url.append("&type-filter={}".format(f))

        for f in flags:
            new_url.append("&flags={}".format(f))

        return self.db_url + ''.join(new_url)

    def _send_DB_request(self, db_url):
        """The passed URL is being sent to the RIPE DEBUG. The function raises
        a custom error based on RIPE's API error list in case of receiving a
        non-expected status code.
        """
        retries = self.max_retries
        logging.debug('Communicator._send_DB_request {}'.format(db_url))
        while True:
            try:
                r = self.session.get(db_url)
                if r.status_code == 200:
                    return r.content
                elif r.status_code == 400:
                    logging.warning("RIPE-API: The service is unable to "
                                    "understand and process the request.")
                    raise errors.RIPEDBError("RIPE-API_ERROR_400")
                elif r.status_code == 403:
                    logging.warning("RIPE-API: Query limit exceeded.")
                    raise errors.RIPEDBError("RIPE-API_ERROR_403")
                elif r.status_code == 404:
                    logging.warning("RIPE-API: No Objects found")
                    raise errors.RIPEDBError("RIPE-API_ERROR_404")
                elif r.status_code == 409:
                    logging.warning("RIPE-API: Integrity constraint violated")
                    raise errors.RIPEDBError("RIPE-API_ERROR_409")
                elif r.status_code == 500:
                    logging.warning("RIPE-API: Internal Server Error")
                    raise errors.RIPEDBError("RIPE-API_ERROR_500")
                else:
                    logging.warning("Unknown RIPE-API response "
                                    "({})".format(r.status_code))
                    raise errors.RIPEDBError("RIPE-API_ERROR_UNKNOWN")
            except requests.ConnectionError as e:
                if retries < 1:
                    raise e
                retries -= 1
                continue
            except:
                raise errors.SendRequestError
