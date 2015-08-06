/**
 * Starts a standard, single process, Node-OFC server
 *
 * Copyright 2015 TTC/Sander Tolsma
 * 
 * See LICENSE file for license
 */

"use strict";

var nodeOFC = require('../lib');

var OFController = nodeOFC.OFController;
var EthSwitch = nodeOFC.apps.ethSwitch;

//
// Create a new Openflow Controller
//
var controller = new OFController({
  debug: true,
  echo: true
});

//
// Install the Ethernet Switch App on the MsgBus
//
var app = new EthSwitch(controller.msgBus, {
  debug: true
});

//
// Start the nodeOFC Controller server
//
controller.start("127.0.0.1", "6633", {
  type: 'TCP',
  debug: false
});