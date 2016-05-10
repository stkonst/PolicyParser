import logging
import math
import multiprocessing as mp
from multiprocessing.queues import SimpleQueue
import sys
import threading
from threading import Thread, Lock
import time
from Queue import Queue, Empty

import analyzer
import communicator
import parsers
import rpsl

threads_count = 10


class FilterResolver:
    def __init__(self, items, ipv6_enabled, blist):

        self.peer_filters = items
        self.ipv6_enabled = ipv6_enabled
        self.black_list = blist

        # Set that contains all the AS sets that we discover via filter
        # parsing and need to be translated into prefix-lists.
        self.AS_set_list = set()

        # Data pool that contains all the AS-SETs that we discovered
        # (included nested ones) to minimise interaction with RIPE-DB
        # (double resolving).
        self.AS_set_dir = rpsl.AsSetObjectDir()

        # Set that contains all the route sets that we discover via filter
        # parsing and need to be translated into prefix-lists.
        self.RS_list = set()

        # Data pool that contains all the RS-SETs that we discovered
        # (included nested ones) to minimise interaction with RIPE-DB
        # (double resolving).
        self.RS_dir = rpsl.RouteSetObjectdir()

        # Set that contains all the ASNs that we discover via filter parsing
        # and need to be translated into prefix-lists.
        self.AS_list = set()

        # Data pool that contains all the ASN objects (including nested ones)
        self.AS_dir = rpsl.AsnObjectDir()

        # The ASes seen through recursive resolving of AS sets. Minimises
        # interaction with RIPE-DB (double resolving).
        self.recursed_ASes = set()

    def resolve_filters(self):
        for pf in self.peer_filters.enumerate_objs():
            # The analyser will analyse the filter and recognise the elements
            # that compose it.
            output_queue, new_ASNs, new_AS_sets, new_RSets = analyzer.analyze_filter(pf.expression)

            self.AS_list.update(new_ASNs)
            self.AS_set_list.update(new_AS_sets)
            self.RS_list.update(new_RSets)

            pf.statements = analyzer.compose_filter(output_queue)

        print "Starting AS sets."
        self._handle_AS_sets()
        print "Starting ASes."
        self._handle_ASes()
        print "Starting RS sets."
        self._handle_RSes()

    def _handle_AS_sets(self):
        """Spawns a process to handle the recursive AS set resolving and
        creates the necessary objects based on the results.
        """
        if len(self.AS_set_list) < 1:
            return

        pool = mp.Pool(1)
        AS_set_directory, self.recursed_ASes = pool.apply(_subprocess_AS_set_resolving, (self.AS_set_list,))
        for setname, children in AS_set_directory.iteritems():
            setObj = rpsl.AsSetObject(setname)
            setObj.AS_set_members.update(children['sets'])
            setObj.ASN_members.update(children['asns'])
            self.AS_set_dir.append_AS_set_obj(setObj)

    def _handle_ASes(self):
        """Spawns several processes (based on the available CPUs) to handle the
        AS resolving and creates the necessary objects based on the results.
        """
        # Gather all the ASNs seen through filter and recursive resolving.
        all_ASNs = list((self.recursed_ASes | self.AS_list) - self.black_list)
        all_ASNs_count = len(all_ASNs)
        if all_ASNs_count < 1:
            return

        # We will devote all but one core to resolving since the main process
        # will handle the objects' creation.
        number_of_resolvers = mp.cpu_count() - 1
        if number_of_resolvers < 1:
            number_of_resolvers = 1

        # The list of ASNs is going to be distributed almost equally to the
        # available resolvers.
        if all_ASNs_count >= number_of_resolvers:
            slice_length = int(math.ceil(all_ASNs_count / float(number_of_resolvers)))
        else:
            number_of_resolvers = all_ASNs_count
            slice_length = 1

        result_q = SimpleQueue()  # NOTE: Only works with this queue.
        processes = []
        slice_start = 0
        for i in xrange(number_of_resolvers):
            ASN_batch = all_ASNs[slice_start:slice_start+slice_length]
            processes.append(mp.Process(target=_subprocess_AS_resolving, args=(ASN_batch, result_q)).start())
            slice_start += slice_length

        # PROGRESS START
        # Show progress while running.
        # Can be safely commented out until PROGRESS END.
        aps_count = 0
        aps = 0
        time_start = time.time()
        # PROGRESS END

        done = 0
        while done < all_ASNs_count:
            try:
                asn, routes = result_q.get()
            except Empty:
                # This should never be reached with this queue but left here
                # just in case.
                time.sleep(0.2)
                continue

            # If the AS has routes create the appropriate ASN object and add it
            # to the data pool.
            if routes is not None and (routes['ipv4'] or routes['ipv6']):
                ASN_object = rpsl.ASObject(asn)
                for prefix in routes['ipv4']:
                    route_object = rpsl.RouteObject(prefix, asn)
                    ASN_object.route_obj_dir.append_route_obj(route_object)
                for prefix in routes['ipv6']:
                    route6_object = rpsl.Route6Object(prefix, asn)
                    ASN_object.route_obj_dir.append_route_obj(route6_object)
                self.AS_dir.append_ASN_obj(ASN_object)
            done += 1

        # PROGRESS START
        # Show progress while running.
        # Can be safely commented out until PROGRESS END.
            aps_count += 1
            time_diff = time.time() - time_start
            if time_diff >= 1:
                aps = aps_count / time_diff
                aps_count = 0
                time_start = time.time()
            sys.stdout.write("{} of {} ASes | {:.0f} ASes/s          \r"
                             .format(done, all_ASNs_count, aps))
            sys.stdout.flush()
        print
        # PROGRESS END

    def _handle_RSes(self):
        """Spawns a process to handle the recursive RS resolving and creates the
        necessary objects based on the results.

        TODO: We can have ASes and AS sets as children so maybe run it before
        the other resolving.
        """
        if len(self.RS_list) < 1:
            return

        pool = mp.Pool(1)
        RS_directory = pool.apply(_subprocess_RS_resolving, (self.RS_list,))
        for setname, children in RS_directory.iteritems():
            route_set_obj = rpsl.RouteSetObject(setname)
            route_set_obj.RSes_dir.update(children['sets'])
            for route in children['routes'].get('ipv4'):
                route_object = rpsl.RouteObject(route, None)  # XXX Do we need origin?
                route_set_obj.members.append_route_obj(route_object)
            for route6 in children['routes'].get('ipv6'):
                route6_object = rpsl.Route6Object(route6, None)  # XXX Do we need origin?
                route_set_obj.mp_members.append_route_obj(route6_object)
            self.RS_dir.append_route_set_obj(route_set_obj)


def _subprocess_init():
    """Tries to apply gevent monkey patching to the spawned process.

    NOTE: The gevent monkey patching is taking place in the spawned process in
    order to not patch the main process' core modules where it is not needed.
    """

    try:
        from gevent import monkey
        monkey.patch_all()
    except ImportError:
        logging.warning("gevent monkey patching could not be applied!"
                        "Make sure gevent and libevent are installed.\nExpect"
                        " the execution time and memory consumption to go up"
                        " otherwise!")


def _subprocess_AS_set_resolving(AS_set_list):
    """Resolves the given AS_set_list recursively.

    This function is going to be spawned as a process that in turn spawns
    threads to handle the network IO.

    Parameters
    ----------
    AS_set_list : set
        The AS sets to be resolved.

    Returns
    -------
    AS_set_directory : dict
        Contains information (children) for all the encountered AS sets.
    recursed_ASes : set
        The ASNs that were found through recursive resolving.
    """
    _subprocess_init()

    comm = communicator.Communicator()
    q = Queue()
    recursed_sets = dict.fromkeys(AS_set_list, '')
    recursed_sets_lock = Lock()
    recursed_ASes = set()
    recursed_ASes_lock = Lock()
    AS_set_directory = dict()
    AS_set_directory_lock = Lock()

    def _threaded_resolve_set():
        """Get an AS set from the queue, resolve it, update the shared
        resources with the results and repeat until signaled to stop.
        This function is going to be spawned as a thread.
        """
        while True:
            current_set = q.get()
            if current_set == 'KILL':
                q.task_done()
                break

            # Recursed AS sets have also depth information.
            if type(current_set) is tuple:
                setname, depth = current_set[0], current_set[1]
            else:
                depth = 1
                setname = current_set

            AS_sets, ASNs = '', ''
            try:
                resp = comm.get_filter_set(setname)
                if resp is None:
                    raise LookupError
                AS_sets, ASNs = parsers.parse_AS_set_members(resp)

            except LookupError:
                logging.error("{}: {}: No Object found for {}"
                              .format(mp.current_process().name,
                                      threading.current_thread().name, setname))

            except Exception as e:
                logging.warning("{}: {}: Failed to resolve DB object {}. {}"
                                .format(mp.current_process().name,
                                        threading.current_thread().name,
                                        setname, e))

            logging.debug("{}: {}: ({})>Found {} ASNs and {} AS-SETs in {}"
                          .format(mp.current_process().name,
                                  threading.current_thread().name, depth,
                                  len(ASNs), len(AS_sets), setname))

            # Enqueue the *new* AS sets for resolving.
            for AS_set in AS_sets:
                with recursed_sets_lock:
                    if recursed_sets.get(AS_set) is None:
                        recursed_sets[AS_set] = ''
                        q.put((AS_set, depth + 1))

            # Update the seen ASes.
            with recursed_ASes_lock:
                recursed_ASes.update(ASNs)

            # Record this AS set's children.
            with AS_set_directory_lock:
                AS_set_directory[setname] = dict(sets=AS_sets, asns=ASNs)

            q.task_done()

    # Enqueue the AS sets present in the filter for resolving.
    for AS_set in AS_set_list:
        q.put(AS_set)

    threads = [Thread(target=_threaded_resolve_set) for _ in xrange(threads_count)]
    for t in threads:
        t.start()
    q.join()

    # When the queue is consumed put poison pills in order to signal the
    # threads to stop.
    for i in xrange(len(threads)):
        q.put('KILL')
    for i, t in enumerate(threads):
        t.join()
    q.join()

    return AS_set_directory, recursed_ASes


def _subprocess_AS_resolving(ASN_batch, result_q):
    """Resolves the given ASN_batch and returns the results throught the
    result_q to the main process.

    This function is going to be spawned as a process that in turn spawns
    threads to handle the network IO.

    Parameters
    ----------
    ASN_batch : list
        The ASNs to be resolved.
    result_q : mp.queues.SimpleQueue
        The queue through which the resolving results are communicated back
        to the main process.
    """
    _subprocess_init()

    comm = communicator.Communicator()
    q = Queue()

    def _threaded_resolve_AS():
        """Get an ASN from the queue, resolve it, return its routes to the
        *main* process and repeat until signaled to stop.
        This function is going to be spawned as a thread.
        """
        while True:
            current_AS = q.get()
            if current_AS == 'KILL':
                q.task_done()
                break

            try:
                resp = comm.get_routes_by_autnum(current_AS, ipv6_enabled=True)
                if resp is None:
                    raise LookupError
                routes = parsers.parse_AS_routes(resp)
            except LookupError:
                logging.warning("{}: {}: No Object found for {}"
                                .format(mp.current_process().name,
                                        threading.current_thread().name,
                                        current_AS))
                routes = None
            except Exception as e:
                logging.error("{}: {}: Failed to resolve DB object {}. {}"
                              .format(mp.current_process().name,
                                      threading.current_thread().name,
                                      current_AS, e))
                routes = None
            result_q.put((current_AS, routes))
            q.task_done()

    # Put the ASNs in the queue to be consumed by the threads.
    for AS in ASN_batch:
        q.put(AS)

    threads = [Thread(target=_threaded_resolve_AS) for _ in xrange(threads_count)]
    for t in threads:
        t.start()
    q.join()

    # When the queue is consumed put poison pills in order to signal the
    # threads to stop.
    for i in xrange(len(threads)):
        q.put('KILL')
    for t in threads:
        t.join()


def _subprocess_RS_resolving(RS_list):
    """Resolves the given RS_list recursively.

    This function is going to be spawned as a process that in turn spawns
    threads to handle the network IO.

    Parameters
    ----------
    RS_list : set
        The RSes to be resolved.

    Returns
    -------
    RS_directory : dict
        Contains information (children) for all the encountered RSes.
    """
    _subprocess_init()

    comm = communicator.Communicator()
    q = Queue()
    recursed_sets = dict.fromkeys(RS_list, '')
    recursed_sets_lock = Lock()
    RS_directory = dict()
    RS_directory_lock = Lock()

    def _threaded_resolve_set():
        """Get an RS from the queue, resolve it, update the shared resources
        with the results and repeat until signaled to stop.
        This function is going to be spawned as a thread.
        """
        while True:
            current_set = q.get()
            if current_set == 'KILL':
                q.task_done()
                break

            # Recursed RSes have also depth information.
            if type(current_set) is tuple:
                setname, depth = current_set[0], current_set[1]
            else:
                depth = 1
                setname = current_set

            RSes, routes = '', ''
            try:
                resp = comm.get_filter_set(setname)
                if resp is None:
                    raise LookupError
                RSes, routes = parsers.parse_RS_members(resp)

            except LookupError:
                logging.error("{}: {}: No Object found for {}"
                              .format(mp.current_process().name,
                                      threading.current_thread().name, setname))

            except Exception as e:
                logging.warning("{}: {}: Failed to resolve DB object {}. {}"
                                .format(mp.current_process().name,
                                        threading.current_thread().name,
                                        setname, e))

            logging.debug("{}: {}: ({})>Found {} RSes and {} routes in {}"
                          .format(mp.current_process().name,
                                  threading.current_thread().name, depth,
                                  len(RSes),
                                  len(routes['ipv4']) + len(routes['ipv6']),
                                  setname))

            # Enqueue the *new* RSes for resolving.
            for route_set in RSes:
                with recursed_sets_lock:
                    if recursed_sets.get(route_set) is None:
                        recursed_sets[route_set] = ''
                        q.put((route_set, depth + 1))

            # Record this RS' children.
            with RS_directory_lock:
                RS_directory[setname] = dict(sets=RSes, routes=routes)

            q.task_done()

    # Enqueue the RSes present in the filter for resolving.
    for route_set in RS_list:
        q.put(route_set)

    threads = [Thread(target=_threaded_resolve_set) for _ in xrange(threads_count)]
    for t in threads:
        t.start()
    q.join()

    # When the queue is consumed put poison pills in order to signal the
    # threads to stop.
    for i in xrange(len(threads)):
        q.put('KILL')
    for i, t in enumerate(threads):
        t.join()
    q.join()

    return RS_directory
