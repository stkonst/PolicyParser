from IPy import IP, IPSet

import errors


def aggregate_prefix_list(plist, t=False):
    '''
    t = if True then truncate, means that will prune the network portion to match the netmask
    (i.e. 1.2.3.4/24 becomes 1.2.3.0/24)
    (i.e. 2001:db8:abcd:1234::dead:beef/64 becomes 2001:db8:abcd:1234::/64
    '''
    s = IPSet()  # the set of aggregated addresses

    for p in plist:
        try:
            ip = IP(p, make_net=t)  # read the line as an IP network; truncate if -t was specified
        except ValueError as err:  # exception if the line can't be parsed as an IP prefix
            raise errors.IPparseError(err)

        s.add(ip)  # add the IP into the set, automatically aggregating as necessary

    result = []
    for prefix in s:
        result.append(str(prefix))

    return result
