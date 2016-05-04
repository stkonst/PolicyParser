Libraries required to be installed before running:
- python requests 2.8.0
- python xxhash 0.4.3
- python gevent 1.1.1

Init flags and parameters

-a	Passing the AS number for resolving its policy.
-o	Passing the name of the output file for exporting the XML policy.
-b  A comma separated list of AS numbers that can be excluded from the resolving.

Usage example:

"python librpsl -a AS3333 -o as3333.xml -b AS1234,AS5678"