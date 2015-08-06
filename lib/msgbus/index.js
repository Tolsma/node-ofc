/**
 * Implement a simple local Node-OFC message bus
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var events = require('events');
var util = require('util');

/**
 * MsgBus Class
 * Implements a simple local message bus
 * 
 * Event domains:
 * - server::*        For all server events
 * - of::*            For all Incomming openflow events (messages)
 * - api::*           For all API events
 *
 * TODO:
 * - implement Multidomain EventEmitter instead of the standard Node EventEmitter
 * - Multi server implementation of Node-OFC cluster working together with an internal and API bus
 */
var MsgBus = module.exports = function MsgBus(config) {
  events.EventEmitter.call(this);
};
util.inherits(MsgBus, events.EventEmitter);

/*
MsgBus.prototype.emit = function() {
  console.log('MsgBus emit: ', arguments);
  events.EventEmitter.prototype.emit.call(this, arguments);
}; */