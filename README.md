# FRITZ Capture 🪤

This is a Python script to obtain packet captures from FRITZ!Boxes.

```
usage: fritz_capture.py [-h] [-f URL] [-u USER] [-p PASSWORD] [-o FILE] [-i INTERFACE] [--check-cert] [--debug]

This script obtains a packet capture from a given FRITZ!Box.

options:
  -h, --help    show this help message and exit
  -f URL        URL of the FRITZ!Box [https://fritz.box]
  -u USER       username to login with [last user logged in]
  -p PASSWORD   password to login with
  -o FILE       output file [stdout]
  -i INTERFACE  interface to capture [1-lan]
  --check-cert  enable certificate check (disabled by default due to self-signed FRITZ!Box certificates)
  --debug       enable debug mode
```

The session handling is based on the example code provided by [AVM](https://avm.de/service/schnittstellen/).

## Usage Examples

The most basic approach is to write to a file using `-o`:
```
# ./fritz_capture.py -o example.pcap
```
This will use the default FRITZ!Box user (i.e. the last user logged in), prompt for the password and write to `example.pcap`. To stop capturing send SIGINT (Ctrl + C).

To view the packet stream live, the packet stream can be piped into tcpdump:
```
# ./fritz_capture.py | tcpdump -r -
```
The same works with Wireshark as well:
```
# ./fritz_capture.py | wireshark -k -i -
```
Using `-i -` Wireshark reads from standard input, with `-k` instructing it to start immediately.

**NOTE:** While the available interfaces differ depending on the FRITZ!Box model, `lan-1` seems to be a reasonable default. If you do not see the expected traffic, consider to chose another interface.

## Background

FRITZ!Boxes allow to obtain packet captures of various interfaces via (https://fritz.box/html/capture.html). There are already several scripts and code snippets available to use this capture interface. However, unable to find a small tool that supports the updated login mechanism introduced in FRITZ!OS 7.24 and uses HTTPS, this script was created.
