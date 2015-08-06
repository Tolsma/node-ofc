/**
 * Implement a generic OpenFlow controller with plugin API
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var MsgBus = require('../msgbus');
var OFSwitch = require('./ofswitch');
var OFServer = require('./ofserver');

/**
 * OFController Class
 * Implements an OpenFlow Controller with events based plugin API
 * 
 * Event domains:
 * - server::*        For all server events
 *
 * TODO:
 * - implement Multidomain EventEmitter instead of the standard Node EventEmitter
 * - implement SSL on TCP connection next to non-SSL TCP connections
 * - implement real Node stream class for switchStream
 *   implement OF version 1.3 Master - Slave etc  <1.3 single tcp connection
 * - Multi server implementation of FlowServers working together with an internal bus and API bus
 * - Using Node Cluster techniques to implement multi core processing for ONE Flowserver
 * 
 */
var OFController = module.exports = function OFController(config) {
  config = config || {};
  this.config = config;
  this.debug = config.debug || false;
  this.echo = config.echo || false;
  
  //
  // Classes to use
  //
  this.msgBus = config.msgBus || new MsgBus(config.msgBus);
  this.OFSwitch = config.OFSwitch || OFSwitch;
  this.OFServer = config.OFServer || OFServer;

  //
  // Create and administer the Server pool
  //
  this.serverTable = {};

  //
  // Create and administer the Switch pool
  //
  this.switchTable = {};
  
  //
  // Initialize this instance
  //
  this.initialize();
};

/**
 * 
 */
OFController.prototype.initialize = function initialize() {
  this.initMsgBusHandling();
};

/**
 * Start the OpenFlow controller TCP and TLS servers on standard or given addresses and ports
 */
OFController.prototype.start = function(address, port, options) {
  var self = this;
  var error, errors = [];
  
  //
  // Create requested server
  //
  function start(address, port, options) {
    if (address && port) {
      port = port || 6653;
      var server = new OFServer(self.msgBus, options);
      error = server.start(address, port);
      if (error) {
        return {
          address: address,
          port: port,
          options: options, 
          error: error
        };
      }
    } else {
      return {
        address: address,
        port: port,
        options: options, 
        error: "No address or port specified!"
      };
    }
  }

  //
  // multiple servers to start from config ?
  //
  var servers = this.config.servers;
  if (servers) {
    // avoid doing it again later
    delete this.config.servers;

    servers.forEach(function(options) {
      var lAddress = options.address;
      var lPort = options.port;
      var lOptions = {
        key: options.key || undefined,
        cert: options.cert || undefined,
        ca: options.ca || undefined,
        type: options.type || "TCP",
        debug: options.debug || self.debug,
        echo: options.echo || self.echo
      };

      error = start(lAddress, lPort, lOptions);
      
      if (error) {
        errors.push(error);
      }
    }, this);
  }

  //
  // only single server to start?
  //
  if (address && port) {
    options = options || {};
    options.debug = options.debug || this.debug;
    options.echo = options.echo || this.echo;
    
    error = start(address, port, options);
    
    if (error) {
      errors.push(error);
    }
  }

  //
  // Return error result
  //
  return errors.length > 0 ? errors : undefined;
};

/*************************************\
 * node-ofc msgBus Event Handling     *
 *************************************/

/**
 * 
 */
OFController.prototype.initMsgBusHandling = function initMsgBusHandling() {
  this.msgBus.on('switch::createOFSwitch', this.onCreateOFSwitch.bind(this));
  this.msgBus.on('switch::removeOFSwitch', this.onRemoveOFSwitch.bind(this));
};

/**
 * Lookup and if no ofswitch with that dpID exists create one and add to msgBus and to switch table
 */
OFController.prototype.onCreateOFSwitch = function onCreateOFSwitch(dpId, features) {
  if (!this.switchTable[dpId]) {
    this.switchTable[dpId] = new this.OFSwitch(features, this.msgBus, {
      debug: this.debug,
      echo: this.echo
    });
  }
};

/**
 * 
 */
OFController.prototype.onRemoveOFSwitch = function onRemoveOFSwitch(dpId) {
  if (!this.switchTable[dpId]) {
    delete this.switchTable[dpId];
  }
};