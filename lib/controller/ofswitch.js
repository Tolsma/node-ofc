/**
 * Implement an Logical OpenFlow Switch mirror
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var util = require('util');

var OFSession = require('./ofsession');
var decode = require('./decoder');
var printer = require('./printer');

/**
 * OFSwitch Class
 * Implements an Logical OpenFlow Switch mirror
 */
var OFSwitch = module.exports = function OFSwitch(features, msgBus, config) {
  this.config = config;
  this.debug = config.debug || false;
  this.echo = config.echo || false;
  this.sessions = {};
  this.msgBus = msgBus;
  this.ports = [];

  //
  // Process the given switch features
  //
  this.processFeatures(features);

  //
  // Initialize this OpenFlow Logical Switch
  //
  this.initialize();
};

/**
 * 
 */
OFSwitch.prototype.initialize = function() {
  //
  // initialize msgBus event handlers
  //
  this.initMsgBusHandling();

  //
  // Handle emit of switch::created event after next tick to create async effect
  //
  this.msgBus.emit('switch::created', this.dpId);
};

/**
 * 
 */
OFSwitch.prototype.processFeatures = function(features) {
  this.dpId = features.datapath_id;               // Datapath unique ID.
  this.nBuffers = features.n_buffers;             // Max packets buffered at once.
  this.ntables = features.n_tables;               // Number of tables supported by datapath.
  this.capabilities = features.capabilities;      // Bitmap of supported "ofp_capabilities".
  this.actions = features.actions;                // Bitmap of supported "ofp_action_type"s.
  
  //
  // Process port features
  //
  features.ports.forEach(this.changePort, this);
};

/**
 * 
 */
OFSwitch.prototype.changePort = function(pf) {
  util.log("[" + this.dpId + "] Port config changed: " + util.inspect(pf, { showHidden: true, depth: null }));
  
  this.ports[pf.port_no] = {
    name        : pf.name,
    hwAddr      : pf.hw_addr,
    config      : pf.config,
    state       : pf.state,
    curr        : pf.curr,
    advertised  : pf.advertised,
    supported   : pf.supported,
    peer        : pf.peer
  };
};

/*************************************\
 * node-ofc msgBus Event Handling     *
 *************************************/

/**
 * 
 */
OFSwitch.prototype.initMsgBusHandling = function initMsgBusHandling() {
  //
  // switch msgBus message handling
  //
  this.msgBus.on('switch::createOFSwitch', this.onCreateOFSwitch.bind(this));
  this.msgBus.on('switch::addSession', this.onAddSession.bind(this));

  //
  // API msgBus message handling
  //
  this.msgBus.on('API::packetOut', this.onPacketOut.bind(this));
  this.msgBus.on('API::flowMod', this.onFlowMod.bind(this));
  this.msgBus.on('API::portMod', this.onPortMod.bind(this));
};

/*************************************\
 * Switch Message Handling           *
 *************************************/

/**
 * Is this for me ? then emit switch::created
 */
OFSwitch.prototype.onCreateOFSwitch = function onCreateOFSwitch(dpId, features) {
  if (this.dpId == dpId) {
    this.msgBus.emit('switch::created', this.dpId);
  }
};

/**
 * 
 */
OFSwitch.prototype.onAddSession = function onAddSession(dpId, sessionData) {
  var self = this;
  var sessionId = sessionData.sessionId;
  var type = sessionData.type;
  var ofVersion = sessionData.ofVersion;
  var socket = sessionData.socket;

  //
  // Create and store OFSession instance
  //
  var session = new OFSession(socket, type, ofVersion, sessionId);
  this.sessions[sessionId] = session;

  //
  // log adition of session
  //
  this.log(session, 'Added session to OFSwitch: ' + sessionData.sessionId);
  
  //
  // Handle incomming data on this new session
  //
  session.on('data', function onData(data) {
    var msgs = session.process(data);
    self.log(session, 'Received ' + msgs.length + ' openflow messages.');
    msgs.forEach(function(msg) {
      if (msg.hasOwnProperty('message')) {
        self.processOFMessage(msg.message, session);
      } else {
        self.log(session, 'Error: Message is unparseable', data);
      }
    });
  });

  //
  // Handle close of this session
  //
  session.on('close', function onClose(data) {
    // 
    // Close session
    //
    self.log(session, "Client Disconnect.", data);
    delete self.sessions[session.sessionId];
    session.close();
    self.log(session, "Client Disconnected");
    
    //
    // Announce that openflow switch can be removed from controller
    //
    self.msgBus.emit('switch::removeOFSwitch', self.dpId);
  });

  //
  // Handle errors on this session
  //
  session.on('error', function onError(data) {
    // TODO
    self.log(session, "Client Error!", data);
    delete self.sessions[session.sessionId];
    session.close();
  });
  
  //
  // Handle socket pause on this session
  //
  session.on('pause', function onPause(data) {
    self.log(session, "Session Paused!");
  });

  //
  // Handle socket resume on this session
  //
  session.on('resume', function onResume(data) {
    self.log(session, "Session Resumed!");
  });

  //
  // Resume data events on the session
  //
  session.resume();
}; 

/*************************************\
 * API Message Handling               *
 *************************************/

/**
 * 
 */
OFSwitch.prototype.onPacketOut = function onPacketOut(dpId, sessionId, message) {
  if (dpId == this.dpId) {
    // TODO Check if session exists
    var session = this.sessions[sessionId];
    var msg = session.createOFMsg(message.type, message.xid);
    msg.message.body = message.body;
    this.log(session, message.type + ' msg send.', msg);
    session.sendMessage(msg);
  }
};

/**
 * 
 */
OFSwitch.prototype.onFlowMod = function onFlowMod(dpId, sessionId, message) {
  if (dpId == this.dpId) {
    // TODO Check if session exists
    var session = this.sessions[sessionId];
    var msg = session.createOFMsg(message.type, message.xid);
    msg.message.body = message.body;
    this.log(session, message.type + ' msg send.', msg);
    session.sendMessage(msg);
  }
};

/**
 * 
 */
OFSwitch.prototype.onPortMod = function onPortMod(dpId, sessionId, message) {
  if (dpId == this.dpId) {
    // TODO Check if session exists
    var session = this.sessions[sessionId];
    var msg = session.createOFMsg(message.type, message.xid);
    msg.message.body = message.body;
    this.log(session, message.type + ' msg send.', msg);
    session.sendMessage(msg);
  }
};

/*************************************\
 * OpenFlow Wire Message Handling     *
 *************************************/

/**
 * 
 */
OFSwitch.prototype.processOFMessage = function processOFMessage(message, session) {
  if (message.hasOwnProperty('header')) {
    var type = message.header.type;
    if (type != 'OFPT_ECHO_REQUEST' || this.echo) {
      this.log(session, type + " msg received !!!");
    }

    if (typeof this[type] == 'function') {
      this[type](message, session);
      return;
    } else {
      this.log(session, "Unknown OF message Type: " + type);
      return;
    }
  } else {
    this.log(session, "Failed to get header:", message);
    return;
  }
};

/**
 * 
 */
OFSwitch.prototype.OFPT_FEATURES_REPLY = function OFPT_FEATURES_REPLY(message, session) {
  // TODO
  this.log(session, "OFPT_FEATURES_REPLY message", message);
};

/**
 * 
 */
OFSwitch.prototype.OFPT_PACKET_IN = function OFPT_PACKET_IN(message, session) {
  var packet = decode.decodeethernet(message.body.data, 0);
  this.log(session, "OFPT_PACKET_IN message \n" + printer.packet(packet));

  this.msgBus.emit('API::OFPT_PACKET_IN', this.dpId, session.sessionId, {
    xid: message.header.xid,
    bufferId: message.body.buffer_id,
    data: packet,
    inPort: message.body.in_port,
    reason: message.body.reason
  });
};

/**
 * 
 */
OFSwitch.prototype.OFPT_FLOW_REMOVED = function OFPT_FLOW_REMOVED(message, session) {
  // TODO
  this.log(session, "OFPT_FLOW_REMOVED message", message);

  this.msgBus.emit('API::OFPT_FLOW_REMOVED', this.dpId, session.sessionId, {
    xid: message.header.xid,
    body: message.body
  });
};

/**
 * 
 */
OFSwitch.prototype.OFPT_PORT_STATUS = function OFPT_PORT_STATUS(message, session) {
  // TODO
  this.log(session, "OFPT_PORT_STATUS message", message);
};

/**
 * 
 */
OFSwitch.prototype.OFPT_ERROR = function OFPT_ERROR(message, session) {
  // TODO Add handling of errors
  this.log(session, "OFPT_ERROR message", message);
};

/**
 * Called when the Logical OpenFlow Switch starts a connection, 
 * TODO: response here with disconnect
 */
OFSwitch.prototype.OFPT_HELLO = function OFPT_HELLO(message, session) {
  this.log(session, "OFPT_HELLO message", message);
};

/**
 * 
 */
OFSwitch.prototype.OFPT_ECHO_REQUEST = function OFPT_ECHO_REQUEST(message, session) {
  var result = session.sendMessage(session.createOFMsg('OFPT_ECHO_REPLY', message.header.xid));
  if (this.echo) {
    this.log(session, "OFPT_ECHO_REPLY msg send", result);
  }
};

/**
 * 
 */
OFSwitch.prototype.OFPT_VENDOR = function OFPT_VENDOR(message, session) {
  // TODO
  this.log(session, "OFPT_VENDOR message", message);
};

/**
 * 
 */
OFSwitch.prototype.log = function log(session, msg, obj) {
  //
  // Create session text
  //
  var sessionTxt = "";
  if (typeof(session) === "object") {
    sessionTxt = "(I " + session.sessionId+ ") ";
  } else {
    obj = msg;
    msg = session;
  }
  
  //
  // Create object text
  //
  var objTxt = obj ? "\n" + util.inspect(obj, false, null) : "";
  
  //
  // Log everything
  //
  if (this.debug) {
    util.log(sessionTxt + msg + objTxt);
  }
};