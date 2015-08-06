/**
 * Decode ethernet protocol data
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

var arp = require('./arp');
var ipv4 = require('./ipv4');
var ipv6 = require('./ipv6');
var unpack = require('./unpack');

//
// Return decoded Ethernet packet info
//
module.exports = function ethernet(raw_packet, offset) {
  var ret = {};
  ret.dhost = unpack.ethernet_addr(raw_packet, 0);
  ret.shost = unpack.ethernet_addr(raw_packet, 6);
  ret.ethertype = unpack.uint16(raw_packet, 12);
  offset = 14;

  // Check for stacked tags in this frame
  switch (ret.ethertype) {
    //
    // VLAN-tagged (802.1Q)
    //
    case 0x8100:
      ret.vlan = vlan(raw_packet, 14);
      // Update the ethertype
      ret.ethertype = unpack.uint16(raw_packet, 16);
      offset = 18;
      break;
    }

  if (ret.ethertype < 1536) {
    // this packet is actually some 802.3 type without an ethertype
    ret.ethertype = 0;
  } else {
    // http://en.wikipedia.org/wiki/EtherType
    switch (ret.ethertype) {
      //
      // IPv4
      //
      case 0x800:
        ret.ip = ipv4(raw_packet, offset);
        break;

      //
      // ARP
      //
      case 0x806:
        ret.arp = arp(raw_packet, offset);
        break;

      //
      // IPv6 - http://en.wikipedia.org/wiki/IPv6
      //
      case 0x86dd:
        ret.ipv6 = ipv6(raw_packet, offset);
        break;

      //
      // LLDP - http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
      //
      case 0x88cc:
        ret.lldp = "need to implement LLDP";
        break;

      //
      // Unknown ethertype
      //
      default:
        console.log("Decoder.js: decode.ethernet() - Don't know how to decode ethertype " + ret.ethertype);
      }
  }
  return ret;
};

// 
// Return decoded 802.1Q header
// http://en.wikipedia.org/wiki/IEEE_802.1Q
//
function vlan(raw_packet, offset) {
  var ret = {};
  ret.priority = (raw_packet[offset] & 0xE0) >> 5;
  ret.canonical_format = (raw_packet[offset] & 0x10) >> 4;
  ret.id = ((raw_packet[offset] & 0x0F) << 8) | raw_packet[offset + 1];
  return ret;
}