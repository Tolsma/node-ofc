/**
 * Decode TCP protocol data
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
// Decode TCP protocol data
// http://en.wikipedia.org/wiki/Transmission_Control_Protocol
//
module.exports = function tcp(raw_packet, offset, ip) {
  var ret = {},
      option_offset,
      options_end;

  ret.sport = unpack.uint16(raw_packet, offset);
  ret.dport = unpack.uint16(raw_packet, offset + 2);
  ret.seqno = unpack.uint32(raw_packet, offset + 4);
  ret.ackno = unpack.uint32(raw_packet, offset + 8);

  // first 4 bits of 12
  ret.data_offset = (raw_packet[offset + 12] & 0xf0) >> 4;
  ret.header_bytes = ret.data_offset * 4;

  // second 4 bits of 12
  ret.reserved = raw_packet[offset + 12] & 15;

  // 13    
  ret.flags = {
    cwr: (raw_packet[offset + 13] & 128) >> 7,
    ece: (raw_packet[offset + 13] & 64) >> 6,
    urg: (raw_packet[offset + 13] & 32) >> 5,
    ack: (raw_packet[offset + 13] & 16) >> 4,
    psh: (raw_packet[offset + 13] & 8) >> 3,
    rst: (raw_packet[offset + 13] & 4) >> 2,
    syn: (raw_packet[offset + 13] & 2) >> 1,
    fin: raw_packet[offset + 13] & 1
  };
  
  ret.window_size = unpack.uint16(raw_packet, offset + 14);
  ret.checksum = unpack.uint16(raw_packet, offset + 16);
  ret.urgent_pointer = unpack.uint16(raw_packet, offset + 18);

  //
  // Get TCP options
  //
  ret.options = {};
  option_offset = offset + 20;
  options_end = offset + ret.header_bytes;
  while (option_offset < options_end) {
    switch (raw_packet[option_offset]) {
      case 0:
        option_offset += 1;
        break;
      case 1:
        option_offset += 1;
        break;
      case 2:
        ret.options.mss = unpack.uint16(raw_packet, option_offset + 2);
        option_offset += 4;
        break;
      case 3:
        ret.options.window_scale = Math.pow(2, (raw_packet[option_offset + 2]));
        option_offset += 3;
        break;
      case 4:
        ret.options.sack_ok = true;
        option_offset += 2;
        break;
      case 5:
        ret.options.sack = [];
        switch (raw_packet[option_offset + 1]) {
          case 10:
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
            option_offset += 10;
            break;
          case 18:
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
            option_offset += 18;
            break;
          case 26:
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
            option_offset += 26;
            break;
          case 34:
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
            ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 26), unpack.uint32(raw_packet, option_offset + 30)]);
            option_offset += 34;
            break;
          default:
            console.log("Invalid TCP SACK option length " + raw_packet[option_offset + 1]);
            option_offset = options_end;
        }
        break;
      case 8:
        ret.options.timestamp = unpack.uint32(raw_packet, option_offset + 2);
        ret.options.echo = unpack.uint32(raw_packet, option_offset + 6);
        option_offset += 10;
        break;
      default:
        throw new Error("Don't know how to process TCP option " + raw_packet[option_offset]);
    }
  }

  // 
  // Get TCP Data
  //
  ret.data_offset = options_end;
  ret.data_end = offset + ip.total_length - ip.header_bytes;
  ret.data_bytes = ret.data_end - ret.data_offset;
  if (ret.data_bytes > 0) {
    //
    // add a buffer slice pointing to the data area of this TCP packet.
    // Note that this does not make a copy, so ret.data is only valid for this current
    // trip through the capture loop.
    //
    ret.data = raw_packet.slice(ret.data_offset, ret.data_end);
    ret.data.length = ret.data_bytes;
  }

  // automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.
  return ret;
};