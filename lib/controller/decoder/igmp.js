/**
 * Decode IGMP protocol data
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
// Decode IGMP protocol data
// http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
//
module.exports = function igmp(raw_packet, offset) {
  var ret = {};

  ret.type = raw_packet[offset];
  ret.max_response_time = raw_packet[offset + 1];
  ret.checksum = unpack.uint16(raw_packet, offset + 2);
  ret.group_address = unpack.ipv4_addr(raw_packet, offset + 4);

  //
  // Do actions on IGMP type
  //
  switch (ret.type) {
    case 0x11:
      ret.version = ret.max_response_time > 0 ? 2: 1;
      ret.type_desc = "Membership Query";
      break;
    case 0x12:
      ret.version = 1;
      ret.type_desc = "Membership Report";
      break;
    case 0x16:
      ret.version = 2;
      ret.type_desc = "Membership Report";
      break;
    case 0x17:
      ret.version = 2;
      ret.type_desc = "Leave Group";
      break;
    case 0x22:
      ret.version = 3;
      ret.type_desc = "Membership Report";
      // TODO: Decode v3 message
      break;
    default:
      ret.type_desc = "type " + ret.type;
      break;
  }
  return ret;
};