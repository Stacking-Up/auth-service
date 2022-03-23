'use strict';

const varAuthController = require('./AuthControllerService');

module.exports.login = function login (req, res, next) {
  varAuthController.login(req.swagger.params, res, next);
};

module.exports.logout = function logout (req, res, next) {
  varAuthController.logout(req.swagger.params, res, next);
};
