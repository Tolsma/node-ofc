/**
 * Implement a generic OpenFlow Session Server (TCP/TLS) with plugin API
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var net = require('net');
var tls = require('tls');
var util = require('util');

var OFSession = require('./ofsession');

/**
 * OFServer Class
 * Implements an OpenFlow TCP/TLS Session Server
 * 
 * Event domains:
 * - server::*        For all server events
 */
var OFServer = module.exports = function OFServer(msgBus, config) {
  config = config || {};
  this.config = config;
  this.debug = config.debug || false;
  this.echo = config.echo || false;
  this.msgBus = msgBus;

  //
  // Store for session parameters when creating OFSwitches
  //
  this._pairing = {};

  //
  // Initialize this OFServer
  //
  this.initialize();
};

/**
 * 
 */
OFServer.prototype.initialize = function() {
  //
  // initialize msgBus event handlers
  //
  this.initMsgBusHandling();
};

/**
 * Start the OpenFlow controller TCP and TLS servers on standard or given addresses and ports
 */
OFServer.prototype.start = function(address, port) {
  //
  // Get config parameters to use and start TCPServer
  //
  address = address || this.config.address;
  port = port || this.config.port;

  if (this.config.type == 'TCP') {
    return this.startTCPServer(address, port);
  } else {
    return this.startTLSServer(address, port);
  }

};

/**
 * 
 */
OFServer.prototype.startTCPServer = function(address, port) {
  var self = this;
  var type = 'TCP';

  //
  // Wait and listen on tcp port
  //
  this.TCPServer = net.createServer();
  this.TCPServer.listen(port, address, function(err, result) {
    self.log("OpenFlow Controller TCPServer listening on " + address + ':' + port);
    self.msgBus.emit('server::started', {
      address: self.TCPServer.address(),
      port: port,
      type: type
    });
  });

  //
  // TCP connection is being made so create new OpenFlow connection session
  //
  this.TCPServer.on('connection', function(socket) {
    self.initializeSession(socket, type);
  });
};

/**
 * 
 */
OFServer.prototype.startTLSServer = function(address, port, options) {
  var self = this;
  var type = 'TLS';

  //
  // Wait and listen on TLS port
  //
  this.TLSServer = tls.createServer(options);
  this.TLSServer.listen(port, address, function(err, result) {
    self.log("OpenFlow Controller TLSServer listening on " + address + ':' + port);
    self.msgBus.emit('server::started', {
      address: self.TLSServer.address(),
      port: port,
      type: type
    });
  });

  //
  // TLS connection is being made so create new OpenFlow connection session
  //
  this.TLSServer.on('connection', function(socket) {
    self.initializeSession(socket, type);
  });
};

/*************************************\
 * node-ofc msgBus Event Handling     *
 *************************************/

/**
 * 
 */
OFServer.prototype.initMsgBusHandling = function initMsgBusHandling() {
  this.msgBus.on('switch::created', this.onCreated.bind(this));
};

/**
 * 
 */
OFServer.prototype.onCreated = function onCreated(dpId) {
  var self = this;
  //
  // Do we have waiting sessions that need to be paired with this OFSwitch instance??
  //
  if (this._pairing[dpId]) {
    this._pairing[dpId].forEach(function(session) {
      //
      // stop handling of current socket events here and add session to OFSwitch
      //
      session.removeListeners();
      self.msgBus.emit('switch::addSession', dpId, session.copy());
    });
    delete this._pairing[dpId];
  }
};

/*************************************\
 * OpenFLow Wire Message Handling     *
 *************************************/

/**
 * 
 */
OFServer.prototype.initializeSession = function(socket, type) {
  var self = this;

  //
  // Create new Openflow Connection Session
  //
  socket.setNoDelay(true);
  var session = new OFSession(socket, type);

  //
  // Handle incomming data on this new connection session
  //
  session.on('data', function onData(data) {
    //
    // Process incomming data
    //
    var msgs = session.process(data);
    self.log(session, 'Received ' + msgs.length + ' openflow messages.');
    msgs.forEach(function(msg) {
      if (msg.hasOwnProperty('message')) {
        self.processOFMessage(msg.message, session);
      } else {
        self.log(session, 'Error: Message is unparseable', msg);
      }
    });
  });

  //
  // Handle close of this session
  //
  session.on('close', function onClose(data) {
    // TODO
    self.log(session, "Client Disconnect.");
    session.close();
  });

  //
  // Handle socket errors on this session
  //
  session.on('error', function onError(data) {
    // TODO
    self.log(session, "Client Error!");
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
  // Log connection
  //
  this.log(session, "Client Connected.");
  self.msgBus.emit('server::connection', {
    sessionId: session.sessionId,
    remoteAddress: socket.remoteAddress,
    remotePort: socket.remotePort,
    localAddress: socket.localAddress,
    localPort: socket.localPort,
    type: type
  });

  //
  // Start with OFPT_HELLO and the highest OF version that we understand...
  //
  this.log(session, "OFPT_HELLO msg send", session.sendMessage(session.createOFMsg('OFPT_HELLO', 1)));
}; 

/**
 * 
 */
OFServer.prototype.processOFMessage = function(message, session) {
  if (message.hasOwnProperty('header')) {
    var type = message.header.type;
    if (type != 'OFPT_ECHO_REQUEST' || this.echo) {
      this.log(session, type + " msg received !!!");
    }
    
    if (typeof this[type] == 'function') {
      this[type](message, session);
      return;
    } else {
      this.log(session, "OF Session not initialized yet so this message could not be processed. Type: " + type);
      return;
    }
  } else {
    this.log(session, "Failed to get header:", message);
    return;
  }
};

/**
 * Called when the Logical OpenFlow Switch starts a connection, bootstraps FEATURE_REQUEST initialize step
 */
OFServer.prototype.OFPT_HELLO = function OFPT_HELLO(message, session) {
  this.log(session, "OFPT_HELLO message", message);

  //
  // Determine the OF protocol version on this session to be used from now on
  //
  session.setVersion(message.version);

  //
  // Get features of the logical OF switch that wants to connect
  //
  this.log(session, "OFPT_FEATURES_REQUEST msg send", session.sendMessage(session.createOFMsg('OFPT_FEATURES_REQUEST', 2)));
};

/**
 * 
 */
OFServer.prototype.OFPT_FEATURES_REPLY = function OFPT_FEATURES_REPLY(message, session) {
  if (message.header.xid == 2 && message.body) {
    this.log(session, "OFPT_FEATURES_REPLY message", message);

    //
    // pause session
    //
    session.pause();

    //
    // Store the session with the correct OFSwitch dpId for later use (switch::created event)
    //
    var features = message.body;
    var dpId = features.datapath_id;

    if (!this._pairing[dpId]) {
      this._pairing[dpId] = [];
    }
    this._pairing[dpId].push(session);

    this.msgBus.emit('switch::createOFSwitch', dpId, features);

  } else {
    this.log(session, "OFPT_FEATURES_REPLY - Received msg with incorrect xid number or missing body, " +
                      "didn't process msg!!");
  }
};

/**
 * 
 */
OFServer.prototype.OFPT_ERROR = function OFPT_ERROR(message, session) {
  // TODO send by the OFSwitch if something went wrong. Add handling of errors
  this.log(session, "OFPT_ERROR message", message);
};

/**
 * 
 */
OFServer.prototype.OFPT_ECHO_REQUEST = function OFPT_ECHO_REQUEST(message, session) {
  var result = session.sendMessage(session.createOFMsg('OFPT_ECHO_REPLY', message.header.xid));
  if (this.echo) {
    this.log(session, "OFPT_ECHO_REPLY msg send", result);
  }
};

/**
 * 
 */
OFServer.prototype.log = function log(session, msg, obj) {
  //
  // Create session text
  //
  var sessionTxt = "";
  if (typeof(session) === "object") {
    sessionTxt = "(S " + session.sessionId+ ") ";
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
  util.log(sessionTxt + msg + objTxt);
};