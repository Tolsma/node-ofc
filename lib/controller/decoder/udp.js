/**
 * Decode UDP protocol data
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

"use strict";

var unpack = require('./unpack');

//
// Decode UDP protocol data
// http://en.wikipedia.org/wiki/User_Datagram_Protocol
//
module.exports = function udp(raw_packet, offset) {
  var ret = {
    sport: unpack.uint16(raw_packet, offset),
    dport: unpack.uint16(raw_packet, offset + 2),
    length: unpack.uint16(raw_packet, offset + 4),
    checksum: unpack.uint16(raw_packet, offset + 6)
  };
  
  if (ret.sport === 53 || ret.dport === 53) {
    ret.dns = this.dns(raw_packet, offset + 8);
  }
  return ret;
};