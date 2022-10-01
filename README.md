# MCTP Emulation Tool

This repo contains an attempt at making an MCTP Endpoint in Rust. This project was inspired
by a need to enable automated testing of the MCTP framework within OpenBMC. 

## Requirements
Here are the current design requirements:
1. Support Simple and Dynamic (bus owners and bridges) Endpoints
2. Support all control messages (mostly a requirement to be a bus owner).
3. Create a pluggable Physical Transport layer to allow any physical interface to be used (E.g. Aardvark I2C adapter,
or local TTY port).
4. Allow network to be defined in some configurable manner (e.g. # of endpoints and network configuration).
5. Capture meaningful metrics about runtime to facilitate automated test requirements (E.g. report # of detected endpoints,
# of control messages received, # of invalid commands received, did discovery complete successfully, any dropped packets, ...).


## Open task list

This is a non-exhaustive list of things that I want to track. This is not everything that needs to be done. Just a list
of interesting (novel) ideas on what needs to be done.

1. Switch `mctp-emu-lib` to using `thiserror` for better error encapsulation
2. Find a better solution for displaying bitfield structures. Might need 2 structures and an automatice `From` interface
to hide this behind the scenes. Ultimately, want to take advantage of all type hints to aid development but still serialize
into the correct wire representation.
3. Support in-kernel networks
4. Support TTY physical transports
5. Support running on a RaspberryPi I2C bus (see `rppal`).
6. Support a Aardvark I2C Adapter
7. Support a Prodigy I3C Adapter
8. Develop an FPGA SPI-to-I3C and/or USB-to-I3C bridge and support it as an Adapter (connect SPI to rPi?).
