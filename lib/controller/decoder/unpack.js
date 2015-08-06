/**
 * Utility functions for decoding raw data packets
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

"use strict";


function lpad(str, len) {
  while (str.length < len) {
    str = "0" + str;
  }
  return str;
}

module.exports = {
  ethernet_addr: function(raw_packet, offset) { 
    return [
      lpad(raw_packet[offset].toString(16), 2),
      lpad(raw_packet[offset + 1].toString(16), 2),
      lpad(raw_packet[offset + 2].toString(16), 2),
      lpad(raw_packet[offset + 3].toString(16), 2),
      lpad(raw_packet[offset + 4].toString(16), 2),
      lpad(raw_packet[offset + 5].toString(16), 2)
    ].join(":"); 
  },
  
  uint16: function(raw_packet, offset) {
    return ((raw_packet[offset] * 256) + raw_packet[offset + 1]);
  },
  
  uint32: function(raw_packet, offset) {
    return (
      (raw_packet[offset] * 16777216) +
      (raw_packet[offset + 1] * 65536) +
      (raw_packet[offset + 2] * 256) +
      raw_packet[offset + 3]
    );
  },
  
  uint64: function(raw_packet, offset) {
    return (
      (raw_packet[offset] * 72057594037927936) +
      (raw_packet[offset + 1] * 281474976710656) +
      (raw_packet[offset + 2] * 1099511627776) +
      (raw_packet[offset + 3] * 4294967296) +
      (raw_packet[offset + 4] * 16777216) +
      (raw_packet[offset + 5] * 65536) +
      (raw_packet[offset + 6] * 256) +
      raw_packet[offset + 7]
    );
  },
    
  ipv4_addr: function(raw_packet, offset) {
    return [
      raw_packet[offset],
      raw_packet[offset + 1],
      raw_packet[offset + 2],
      raw_packet[offset + 3]
    ].join('.');
  },
  
  ipv6_addr: function(raw_packet, offset) {
    var ret = '';
    for (var i = offset; i < offset + 16; i += 2) {
      if (i > offset) {
        ret += ':';
      }
      ret += this.uint16(raw_packet, i).toString(16);
    }
    // TODO: do a better job to compress out largest run of zeros.
    return ret.replace(/(0:)+/, ':');
  }
};