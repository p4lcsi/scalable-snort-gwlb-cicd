DAQ GWLB

Simple DAQ to use for GWLB use case.

This DAQ works in inline mode. It is expected that packets arriving on this interface
are geneve encapsulated packets.

Incoming packets are handed off to snort as expected. Outgoing packets have their
L2 and L3 addresses swapped to support AWS GWLB use case.

The minimal arguments to use this DAQ is
    snort --daq gwlb -i <intf> --snap <snap len>

Be sure to set snap len to accomodate an Ether MTU sized packet plus geneve header and inner packet!
