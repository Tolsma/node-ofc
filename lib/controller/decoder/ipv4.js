/**
 * Decode IPv4 protocol data
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
// Return decoded IPv4 info
// http://en.wikipedia.org/wiki/IPv4
//
module.exports = function ipv4(raw_packet, offset) {
  var ret = {};

  // first 4 bits
  ret.version = (raw_packet[offset] & 240) >> 4;
  
  // second 4 bits
  ret.header_length = raw_packet[offset] & 15;
  ret.header_bytes = ret.header_length * 4;

  // 1
  ret.diffserv = raw_packet[offset + 1];

  // 2, 3
  ret.total_length = unpack.uint16(raw_packet, offset + 2);
  
  // 4, 5
  ret.identification = unpack.uint16(raw_packet, offset + 4);
  
  // 3-bits from 6
  ret.flags = {};
  ret.flags.reserved = (raw_packet[offset + 6] & 128) >> 7;
  ret.flags.df = (raw_packet[offset + 6] & 64) >> 6;
  ret.flags.mf = (raw_packet[offset + 6] & 32) >> 5;
  
  // 13-bits from 6, 7
  ret.fragment_offset = ((raw_packet[offset + 6] & 31) * 256) + raw_packet[offset + 7];
  
  // 8, 9, 10, 11
  ret.ttl = raw_packet[offset + 8];
  ret.protocol = raw_packet[offset + 9];
  ret.header_checksum = unpack.uint16(raw_packet, offset + 10);
  
  // 12, 13, 14, 15
  ret.saddr = unpack.ipv4_addr(raw_packet, offset + 12);
  
  // 16, 17, 18, 19
  ret.daddr = unpack.ipv4_addr(raw_packet, offset + 16);
  
  //
  // TODO - parse IP "options" if header_length > 5
  //
  
  //
  // Decode rest of IPv4 packet data
  //
  switch (ret.protocol) {
    case 1:
      ret.protocol_name = "ICMP";
      ret.icmp = icmp(raw_packet, offset + (ret.header_length * 4));
      break;
    case 2:
      ret.protocol_name = "IGMP";
      ret.igmp = igmp(raw_packet, offset + (ret.header_length * 4));
      break;
    case 6:
      ret.protocol_name = "TCP";
      ret.tcp = tcp(raw_packet, offset + (ret.header_length * 4), ret);
      break;
    case 17:
      ret.protocol_name = "UDP";
      ret.udp = udp(raw_packet, offset + (ret.header_length * 4));
      break;
    default:
      ret.protocol_name = "Unknown";
    }
  return ret;
};