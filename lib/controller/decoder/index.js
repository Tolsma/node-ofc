/**
 * Generic decode data packets functions
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

"use strict";

var ethernet = require('./ethernet');
var ipv4 = require('./ipv4');
var ipv6 = require('./ipv6');

//
// Decoding functions
//
exports.dump_bytes = function dump_bytes(raw_packet, offset) {
  for (var i = offset; i < raw_packet.length; i += 1) {
    console.log(i + ": " + raw_packet[i]);
  }
};

exports.decodeethernet = function decodeethernet(raw_packet, offset) { 
  return ethernet(raw_packet, offset);
};


// an oddity about nulltype is that it starts with a 4 byte header, but I can't find a
// way to tell which byte order is used.  The good news is that all address family
// values are 8 bits or less.
function nulltype(raw_packet, offset) {
  var ret = {};

  if (raw_packet[0] === 0 && raw_packet[1] === 0) {
    // must be one of the endians
    ret.pftype = raw_packet[3];
  } else {
    // and this is the other one
    ret.pftype = raw_packet[0];
  }

  if (ret.pftype === 2) {
    // AF_INET, at least on my Linux and OSX machines right now
    ret.ip = ipv4(raw_packet, 4);
  } else if (ret.pftype === 30) {
    // AF_INET6, often
    ret.ip = ipv6(raw_packet, 4);
  } else {
    console.log("Decoder.js: decode.nulltype() - Don't know how to decode protocol family " + ret.pftype);
  }

  return ret;
}