'use strict';

const varAuthController = require('./AuthControllerService');

module.exports.login = function login (req, res, next) {
  varAuthController.login(req.swagger.params, res, next);
};
