/**
 * Decode DNS protocol data
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
// Decode DNS protocol data
// http://tools.ietf.org/html/rfc1035
//
module.exports = function dns(raw_packet, offset) {
  var ret = {},
      i,
      internal_offset,
      question_done,
      len,
      parts;

  //
  // Decode DNS Header
  //
  ret.header = {
    id: unpack.uint16(raw_packet, offset),
    qr: (raw_packet[offset + 2] & 128) >> 7,
    opcode: (raw_packet[offset + 2] & 120) >> 3,
    aa: (raw_packet[offset + 2] & 4) >> 2,
    tc: (raw_packet[offset + 2] & 2) >> 1,
    rd: raw_packet[offset + 2] & 1,
    ra: (raw_packet[offset + 3] & 128) >> 7,
    z: 0,
    rcode: raw_packet[offset + 3] & 15,
    qdcount: unpack.uint16(raw_packet, offset + 4),
    ancount: unpack.uint16(raw_packet, offset + 6),
    nscount: unpack.uint16(raw_packet, offset + 8),
    arcount: unpack.uint16(raw_packet, offset + 10),
  };
  
  //
  // Decode other DNS protocol data
  //
  internal_offset = offset + 12;
  ret.question = [];
  for (i = 0; i < ret.header.qdcount; i += 1) {
    ret.question[i] = {};
    question_done = false;
    parts = [];
    while (!question_done && internal_offset < raw_packet.Decoder_header.caplen) {
      len = raw_packet[internal_offset];
      if (len > 0) {
        parts.push(raw_packet.toString("ascii", internal_offset + 1, internal_offset + 1 + len));
      } else {
        question_done = true;
      }
      internal_offset += (len + 1);
    }
    ret.question[i].qname = parts.join('.');
    ret.question[i].qtype = qtype_to_string(unpack.uint16(raw_packet, internal_offset));
    internal_offset += 2;
    ret.question[i].qclass = qclass_to_string(unpack.uint16(raw_packet, internal_offset));
    internal_offset += 2;
  }

  // TODO - actual hard parts here, understand RR compression scheme, etc.
  ret.answer = {};
  ret.authority = {};
  ret.additional = {};

  return ret;
};

function type_to_string(type_num) {
  switch (type_num) {
    case 1:
      return "A";
    case 2:
      return "NS";
    case 3:
      return "MD";
    case 4:
      return "MF";
    case 5:
      return "CNAME";
    case 6:
      return "SOA";
    case 7:
      return "MB";
    case 8:
      return "MG";
    case 9:
      return "MR";
    case 10:
      return "NULL";
    case 11:
      return "WKS";
    case 12:
      return "PTR";
    case 13:
      return "HINFO";
    case 14:
      return "MINFO";
    case 15:
      return "MX";
    case 16:
      return "TXT";
    default:
      return ("Unknown (" + type_num + ")");
  }
}

function qtype_to_string(qtype_num) {
  switch (qtype_num) {
    case 252:
      return "AXFR";
    case 253:
      return "MAILB";
    case 254:
      return "MAILA";
    case 255:
      return "*";
    default:
      return type_to_string(qtype_num);
  }
}

function class_to_string(class_num) {
  switch (class_num) {
    case 1:
      return "IN";
    case 2:
      return "CS";
    case 3:
      return "CH";
    case 4:
      return "HS";
    default:
      return "Unknown (" + class_num + ")";
  }
}

function qclass_to_string(qclass_num) {
  if (qclass_num === 255) {
    return "*";
  } else {
    return class_to_string(qclass_num);
  }
}