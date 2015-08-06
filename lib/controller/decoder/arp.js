/**
 * Decode ARP protocol data
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
// Return decoded arp information
// http://en.wikipedia.org/wiki/Address_Resolution_Protocol
//
module.exports = function arp(raw_packet, offset) {
  var ret = {};

  ret.htype = unpack.uint16(raw_packet, offset);
  ret.ptype = unpack.uint16(raw_packet, offset + 2);
  ret.hlen = raw_packet[offset + 4];
  ret.plen = raw_packet[offset + 5];
  ret.operation = unpack.uint16(raw_packet, offset + 6);
  
  if (ret.operation === 1) {
    ret.operation = "request";
  }
  else if (ret.operation === 2) {
    ret.operation = "reply";
  }
  else {
    ret.operation = "unknown";
  }
  
  // ethernet + IPv4   
  if (ret.hlen === 6 && ret.plen === 4) {
    ret.sender_ha = unpack.ethernet_addr(raw_packet, offset + 8);
    ret.sender_pa = unpack.ipv4_addr(raw_packet, offset + 14);
    ret.target_ha = unpack.ethernet_addr(raw_packet, offset + 18);
    ret.target_pa = unpack.ipv4_addr(raw_packet, offset + 24);
  }

  //
  // TODO:
  // don't know how to decode more exotic ARP types
  //
 
  return ret;
};