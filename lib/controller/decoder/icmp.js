/**
 * Decode ICMP protocol data
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
// Decode ICPM protocol data
// http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
//
module.exports = function icmp(raw_packet, offset) {
  var ret = {};

  ret.type = raw_packet[offset];
  ret.code = raw_packet[offset + 1];
  ret.checksum = unpack.uint16(raw_packet, offset + 2);
  ret.id = unpack.uint16(raw_packet, offset + 4);
  ret.sequence = unpack.uint16(raw_packet, offset + 6);

  //
  // Do actions depending on ICMP type
  //
  switch (ret.type) {
    case 0:
      ret.type_desc = "Echo Reply";
      break;
    case 1:
    case 2:
      ret.type_desc = "Reserved";
      break;
    case 3:
      switch (ret.code) {
        case 0:
          ret.type_desc = "Destination Network Unreachable";
          break;
        case 1:
          ret.type_desc = "Destination Host Unreachable";
          break;
        case 2:
          ret.type_desc = "Destination Protocol Unreachable";
          break;
        case 3:
          ret.type_desc = "Destination Port Unreachable";
          break;
        case 4:
          ret.type_desc = "Fragmentation required, and DF flag set";
          break;
        case 5:
          ret.type_desc = "Source route failed";
          break;
        case 6:
          ret.type_desc = "Destination network unknown";
          break;
        case 7:
          ret.type_desc = "Destination host unknown";
          break;
        case 8:
          ret.type_desc = "Source host isolated";
          break;
        case 9:
          ret.type_desc = "Network administratively prohibited";
          break;
        case 10:
          ret.type_desc = "Host administratively prohibited";
          break;
        case 11:
          ret.type_desc = "Network unreachable for TOS";
          break;
        case 12:
          ret.type_desc = "Host unreachable for TOS";
          break;
        case 13:
          ret.type_desc = "Communication administratively prohibited";
          break;
        default:
          ret.type_desc = "Destination Unreachable (unknown code " + ret.code + ")";
      }
      break;
    case 4:
      ret.type_desc = "Source Quench";
      break;
    case 5:
      switch (ret.code) {
        case 0:
          ret.type_desc = "Redirect Network";
          break;
        case 1:
          ret.type_desc = "Redirect Host";
          break;
        case 2:
          ret.type_desc = "Redirect TOS and Network";
          break;
        case 3:
          ret.type_desc = "Redirect TOS and Host";
          break;
        default:
          ret.type_desc = "Redirect (unknown code " + ret.code + ")";
          break;
      }
      break;
    case 6:
      ret.type_desc = "Alternate Host Address";
      break;
    case 7:
      ret.type_desc = "Reserved";
      break;
    case 8:
      ret.type_desc = "Echo Request";
      break;
    case 9:
      ret.type_desc = "Router Advertisement";
      break;
    case 10:
      ret.type_desc = "Router Solicitation";
      break;
    case 11:
      switch (ret.code) {
        case 0:
          ret.type_desc = "TTL expired in transit";
          break;
        case 1:
          ret.type_desc = "Fragment reassembly time exceeded";
          break;
        default:
          ret.type_desc = "Time Exceeded (unknown code " + ret.code + ")";
      }
      break;
    //
    // TODO - decode the rest of the well-known ICMP messages
    //
    default:
      ret.type_desc = "type " + ret.type + " code " + ret.code;
  }

  // There are usually more exciting things hiding in ICMP packets after the headers
  return ret;
};