/**
 * Decode IPv6 protocol data
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

"use strict";

var icmp = require('./icmp');
var igmp = require('./igmp');
var tcp = require('./tcp');
var udp = require('./udp');
var unpack = require('./unpack');

//
// Return decoded IPv6 packet
// http://en.wikipedia.org/wiki/IPv6
//
module.exports = function ip6(raw_packet, offset) {
  var ret = {};

  // first 4 bits
  ret.version = (raw_packet[offset] & 240) >> 4;
  
  // next 40 bytes
  ret.traffic_class = ((raw_packet[offset] & 15) << 4) + ((raw_packet[offset + 1] & 240) >> 4);
  ret.flow_label = ((raw_packet[offset + 1] & 15) << 16) +
  (raw_packet[offset + 2] << 8) +
  raw_packet[offset + 3];
  ret.payload_length = unpack.uint16(raw_packet, offset + 4);
  ret.total_length = ret.payload_length + 40;
  ret.next_header = raw_packet[offset + 6];
  ret.hop_limit = raw_packet[offset + 7];
  ret.saddr = unpack.ipv6_addr(raw_packet, offset + 8);
  ret.daddr = unpack.ipv6_addr(raw_packet, offset + 24);
  ret.header_bytes = 40;

  ip6_header(raw_packet, ret.next_header, ret, offset + 40);
  return ret;
};

//
// Return decoded IPv6 header
// http://en.wikipedia.org/wiki/IPv6
//
function ip6_header(raw_packet, next_header, ip, offset) {
  switch (next_header) {
    case 1:
      ip.protocol_name = "ICMP";
      ip.icmp = icmp(raw_packet, offset);
      break;
    case 2:
      ip.protocol_name = "IGMP";
      ip.igmp = igmp(raw_packet, offset);
      break;
    case 6:
      ip.protocol_name = "TCP";
      ip.tcp = tcp(raw_packet, offset, ip);
      break;
    case 17:
      ip.protocol_name = "UDP";
      ip.udp = udp(raw_packet, offset);
      break;
    default:
      //
      // TODO: capture the extensions
      // decode.ip6_header(raw_packet, raw_packet[offset], offset + raw_packet[offset + 1]);
      //
  }
}