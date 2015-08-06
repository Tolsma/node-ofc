/**
 * Implement a simple Ethernet switch on top of a Node-OFC System
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var util = require('util');

/**
 * Switch Class
 * Implement an Ethernet Switch on top of a Node-OFC System bus
 */
var Switch = module.exports = function Switch(msgBus, config) {
  config = config || {};
  this.debug = config.debug || false;
  this.msgBus = msgBus;
  
  //
  // Initialize MAC table store
  //
  this.l2table = {};

  //
  // initialize msgBus event handlers
  //
  this.initMsgBusHandling();
};

/*************************************\
 * node-ofc msgBus Event Handling     *
 *************************************/

/**
 * 
 */
Switch.prototype.initMsgBusHandling = function initMsgBusHandling() {
  this.msgBus.on('API::OFPT_PACKET_IN', this.OFPT_PACKET_IN.bind(this));
  this.msgBus.on('API::OFPT_FLOW_REMOVED', this.OFPT_FLOW_REMOVED.bind(this));
};  

/**
 * 
 */
Switch.prototype.OFPT_PACKET_IN = function OFPT_PACKET_IN(dpId, sessionId, obj) {
  this.log(util.format("Packet received with source: %s \tdest: %s\tin_port: %s", obj.data.shost, obj.data.dhost, obj.inPort));

  this.doL2Learning(dpId, sessionId, obj, obj.data);
  this.forwardL2Packet(dpId, sessionId, obj, obj.data);
};

/**
 * 
 */
Switch.prototype.OFPT_FLOW_REMOVED = function OFPT_FLOW_REMOVED(dpId, sessionId, obj) {
  this.log(util.format("Flow removed: %s \n", util.inspect(obj, false, null)));

  this.doFlush(dpId, obj.body.match.dl_dst);
};

/*************************************\
 * Other class functions              *
 *************************************/

/**
 * 
 */
Switch.prototype.doL2Learning = function doL2Learning(dpId, sessionId, obj, packet) {
  var dlSrc = packet.shost;
  var inPort = obj.inPort;

  //
  // valid source MAC address to learn?
  //
  if (dlSrc == 'ff:ff:ff:ff:ff:ff') {
    this.log('*Warning* Source set to Broadcast');
    return;
  }

  //
  // create and get MAC Table for given OFSwitch (dpId)
  //
  if (!this.l2table.hasOwnProperty(dpId)) {
    this.l2table[dpId] = {};
  }
  var macTable = this.l2table[dpId];

  //
  // learn MAC address if not known or change if known or other port
  //
  if (macTable.hasOwnProperty(dlSrc)) {
    var dst = macTable[dlSrc];
    if (dst != inPort) {
      // MAC address is already learned from other port so change
      this.log("MAC has moved from " + dst + " to " + inPort);
      macTable[dlSrc] = inPort;
      //
      // TODO: remove existing (wrong) flow??
      //
    } else {
      // already learned for this port but possibly flow removed or flow table out of sync with
      // OF switch so add flow again
      return;
    }
  } else {
    // new MAC address
    this.log("learned mac " + dlSrc + " port : " + inPort);
    macTable[dlSrc] = inPort;
  }
  
  this.log(util.inspect(this.l2table, false, null));
};

/**
 * 
 */
Switch.prototype.doFlush = function doFlush(dpId, macAddr) {
  var macTable = this.l2table[dpId];
  var port = macTable[macAddr];

  delete macTable[macAddr];
  this.log("Flushed mac " + macAddr + " port : " + port);
  this.log(util.inspect(this.l2table, false, null));
};

/**
 * 
 */
Switch.prototype.forwardL2Packet = function forwardL2Packet(dpId, sessionId, obj, packet) {
  var dlDst = packet.dhost;
  var dlSrc = packet.shost;
  var macTable = this.l2table[dpId];
  var inPort = macTable[dlSrc];
  var outMsg;

  // handle packet when not broadcast and when we know where the destination mac is: create flow 
  if ((dlDst != 'ff:ff:ff:ff:ff:ff') && macTable.hasOwnProperty(dlDst)) {
    // Destination port
    var prt = macTable[dlDst];

    if (prt !== inPort) {
      this.log(util.format("Installing flow for destination: %s \tout_port: %s", dlDst, prt));
      outMsg = this.setFlowModMsg(obj, packet, prt);
      this.msgBus.emit('API::flowMod', dpId, sessionId, outMsg);
    } else {
      // if in-port is out-port (under normal circumstances not possible!!!)
      this.log("*warning* Forward in port = " + inPort + " is out port = " + prt);
    }
  } else {
    // This packet still needs to be send: so flood instead...
    this.log("Flooding Buffer Id:" + obj.bufferId);
    outMsg = this.setOutFloodMsg(obj, inPort);
    this.msgBus.emit('API::packetOut', dpId, sessionId, outMsg);
  }
};

/**
 * 
 */
Switch.prototype.setOutFloodMsg = function setOutFloodMsg(obj, inPort) {
  return {
    type: 'OFPT_PACKET_OUT',
    xid: 0x03,
    body: {
      buffer_id: obj.bufferId,
      in_port: inPort,
      actions: [{
        header: {
          type: 'OFPAT_OUTPUT'
        },
        body: {
          port: 'OFPP_FLOOD'
        },
      }]
    }
  };
};

/**
 * 
 */
Switch.prototype.setFlowModMsg = function setFlowModMsg(obj, packet, outPort) {
  var flow = this.extractEthFlow(packet);
  return {
    type: 'OFPT_FLOW_MOD',
    xid: 0x04,
    body: {
      command: 'OFPFC_ADD',
      cookie: flow.dl_dst,
      hard_timeout: 0,
      idle_timeout: 100,
      priority: 0x8000,
      buffer_id: obj.bufferId,
      out_port: 'OFPP_NONE',
      flags: ['OFPFF_SEND_FLOW_REM'],
      // 
      // Match in openflow 1.0 is without header and body. Find out how to implement cross version....
      //
      match: {
        header: {
          type: 'OFPMT_STANDARD'
        },
        body: flow
      },
      actions: {
        header: {
          type: 'OFPAT_OUTPUT'
        },
        body: {
          port: outPort
        }
      }
    }
  };
};

/**
 *
 */
Switch.prototype.extractEthFlow = function extractEthFlow(packet) {
  return {
    dl_dst: packet.dhost,
    dl_vlan: packet.vlan || 'OFP_VLAN_NONE'
  };
};

/**
 *
 */
Switch.prototype.log = function log(text) {
  if (this.debug) {
    util.log(text);
  }
};