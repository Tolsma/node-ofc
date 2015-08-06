/**
 * Simple text printer for common data packet types
 *
 * Borrowed parts from node-pcap; Thanks to the author!!
 * Copyright 2015 TTC/Sander Tolsma
 * Copyright 2010 Matthew Ranney
 * 
 * See LICENSE file for license
 */

"use strict";

var util = require('util'); 

//
// simple printers for common types
//
module.exports = {
  /**
   * 
   */
  dns: function (packet) {
    var ret = " DNS",
        dns = packet.ip.udp.dns;
  
    if (dns.header.qr === 0) {
      ret += " question";
    } else if (dns.header.qr === 1) {
        ret += " answer";
    } else {
        return " DNS format invalid: qr = " + dns.header.qr;
    }
  
    return ret + " " + dns.question[0].qname + " " + dns.question[0].qtype;
  },
  
  /**
   * 
   */
  ipv4: function(packet) {
    var ret = "",
        ip = packet.ip;
  
    switch (ip.protocol_name) {
      case "TCP":
        ret += " " + ip.saddr + ":" + ip.tcp.sport + " -> " + ip.daddr + ":" + ip.tcp.dport +
        " TCP len " + ip.total_length + " [" +
        Object.keys(ip.tcp.flags).filter(function(v) {
          if (ip.tcp.flags[v] === 1) {
            return true;
          }
        }).join(",") + "]";
        break;
      case "UDP":
        ret += " " + ip.saddr + ":" + ip.udp.sport + " -> " + ip.daddr + ":" + ip.udp.dport;
        if (ip.udp.sport === 53 || ip.udp.dport === 53) {
          ret += print.dns(packet);
        } else {
          ret += " UDP len " + ip.total_length;
        }
        break;
      case "ICMP":
        ret += " " + ip.saddr + " -> " + ip.daddr + " ICMP " + ip.icmp.type_desc + " " + ip.icmp.sequence;
        break;
      case "IGMP":
        ret += " " + ip.saddr + " -> " + ip.daddr + " IGMP " + ip.igmp.type_desc + " " + ip.igmp.group_address;
        break;
      default:
        ret += " proto " + ip.protocol_name;
        break;
    }
    return ret;
  },
  
  /**
   * 
   */
  arp: function(packet) {
    var ret = "",
        arp = packet.arp;
        
    if (arp.htype === 1 && arp.ptype === 0x800 && arp.hlen === 6 && arp.plen === 4) {
      ret += " " + arp.sender_pa + " ARP " + arp.operation + " " + arp.target_pa;
      if (arp.operation === "reply") {
        ret += " hwaddr " + arp.target_ha;
      }
    } else {
      ret = " unknown arp type" + util.inspect(arp);
    }
    return ret;
  },
  
  /**
   * 
   */
  ethernet: function(packet) {
    var ret = packet.shost + " -> " + packet.dhost;
    switch (packet.ethertype) {
      case 0x0:
        ret += " 802.3 type ";
        break;
      case 0x800:
        ret += this.ipv4(packet);
        break;
      case 0x806:
        ret += this.arp(packet);
        break;
      case 0x86dd:
        ret += " IPv6 ";
        break;
      case 0x88cc:
        ret += " LLDP ";
        break;
      default:
        console.log("Printer: ethernet() - Don't know how to print ethertype " + packet.ethertype);
      }
    return ret;
  },
  
  /**
   * 
   */
  rawtype: function(packet) {
    return "raw" + this.ip(packet);
  },
  
  /**
   * 
   */
  nulltype: function(packet) {
    var ret = "loopback";
  
    if (packet.pftype === 2) {
      // AF_INET, at least on my Linux and OSX machines right now
      ret += print.ip(packet);
    } else if (packet.pftype === 30) {
      // AF_INET6, often
      console.log("Printer: nulltype() - Don't know how to print IPv6 packets.");
    } else {
      console.log("Printer: nulltype() - Don't know how to print protocol family " + packet.pftype);
    }
    return ret;
  },
  
  /**
   * 
   */
  packet: function(packet_to_print) {
    return this.ethernet(packet_to_print);
  }
};