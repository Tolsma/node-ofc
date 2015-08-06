/**
 * Implement a generic OF Session class
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var oflib = require('oflib-node');

/**
 * OFSession Class
 * Implement a generic OpenFlow Session with an Openflow capable node (for example switch)
 */
var OFSession = module.exports = function OFSession(socket, type, ofVersion, sessionId) {
  this._events = [];

  //
  // save given variables
  //
  this.type = type;
  this._socket = socket;

  //
  // Standard OF variables
  //
  this._switchStream = new oflib.Stream();
  this._ofSizes = oflib.ofp.sizes;
  
  //
  // Create convenience property for reading a sessionId
  //
  this.sessionId = sessionId || socket.remoteAddress + ":" + socket.remotePort;
  
  //
  // Highest ofVersion to start this session with....
  //
  this.ofVersion = ofVersion || oflib.version;
};

/**
 * Close this session
 */
OFSession.prototype.close = function close() {
  this.pause();
  this.removeListeners();
  delete this._msgBuffer;
  delete this._events;
  delete this._switchStream;
  delete this._ofSizes;
  delete this.type;
  delete this._socket;
  delete this.sessionId;
  delete this.ofVersion;
};

/**
 * 
 */
OFSession.prototype.process = function process(data) {
  return this._switchStream.process(data);
};

/**
 * 
 */
OFSession.prototype.setVersion = function setVersion(version) {
  //
  // Determine the OF protocol version on this session to be used from now on
  //
  this.ofVersion = version < this.ofVersion ? version : this.ofVersion;
};

/**
 * 
 */
OFSession.prototype.copy = function copy() {
  return {
    sessionId: this.sessionId,
    type: this.type,
    ofVersion: this.ofVersion,
    socket: this._socket
  };
};

/**
 * 
 */
OFSession.prototype.on = function on(event, cb) {
  this._events.push({
    event: event,
    cb: cb
  });
  this._socket.on(event, cb);
};

/**
 * 
 */
OFSession.prototype.removeListeners = function removeListeners() {
  var self = this;
  
  this._events.forEach(function(el) {
    self._socket.removeListener(el.event, el.cb);
  });
  this._events = [];
};

/**
 * 
 */
OFSession.prototype.pause = function pause() {
  return this._socket.pause();
};

/**
 * 
 */
OFSession.prototype.resume = function resume() {
  return this._socket.resume();
};

/**
 * 
 */
OFSession.prototype.sendMessage = function sendMessage(obj) {
  var buf = new Buffer(this.getSize(obj));
  var pack = oflib.pack(obj, buf, 0);

  if (!('error' in pack)) {
    this._socket.write(buf);
  } else {
    return pack;
  }
  
  pack.warnings = pack.warnings || [];
  pack.warnings.push(obj.message.header.type + " msg send.");
  return pack;
};

/**
 * TODO: create dynamic length parser instead of table lookup!!!
 */
OFSession.prototype.getSize = function getSize(obj) {
  var translate = {
    // temporary
    ofpt_header           : 8,
    ofpt_hello            : 8,
    ofpt_echo_reply       : 8,
    ofpt_echo_request     : 8,
    ofpt_features_request : 8,
    ofpt_flow_mod         : 72 + 8,
    ofpt_packet_out       : 16 + 8
/*    ofpt_header: "ofp_header",
    ofpt_hello: "ofp_hello",
    "ofp_switch_config",
    "ofp_phy_port",
    ofpt_features_request: "ofp_switch_features",
    "ofp_port_status",
    "ofp_port_mod",
    "ofp_packet_in",
    "ofp_action_output",
    "ofp_action_vlan_vid",
    "ofp_action_vlan_pcp",
    "ofp_action_dl_addr",
    "ofp_action_nw_addr",
    "ofp_action_tp_port",
    "ofp_action_nw_tos",
    "ofp_action_vendor_header",
    "ofp_action_header",
    ofpt_packet_out: "ofp_packet_out",
    "ofp_match",
    ofpt_flow_mod: "ofp_flow_mod",
    "ofp_flow_removed",
    "ofp_error_msg",
    "ofp_stats_request",
    "ofp_stats_reply",
    "ofp_desc_stats",
    "ofp_flow_stats_request",
    "ofp_flow_stats",
    "ofp_aggregate_stats_request",
    "ofp_aggregate_stats_reply",
    "ofp_table_stats",
    "ofp_port_stats_request",
    "ofp_port_stats",
    "ofp_vendor_header",
    "ofp_queue_prop_header",
    "ofp_queue_prop_min_rate",
    "ofp_packet_queue",
    "ofp_queue_get_config_request",
    "ofp_queue_get_config_reply",
    "ofp_action_enqueue",
    "ofp_queue_stats_request",
    "ofp_queue_stats"  */
  };
  var type = obj.message.header.type.toLowerCase();
  return translate[type];
};

/**
 * 
 */
OFSession.prototype.createOFMsg = function createOFMsg(type, xid) {
  return {
    message: {
      "header": {
        "type": type,
        "xid": xid || 1 //don't care?
      },
      "version": this.ofVersion,
      "body": {}
    }
  };
};