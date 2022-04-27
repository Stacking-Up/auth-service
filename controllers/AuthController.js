'use strict';

const varAuthController = require('./AuthControllerService');

module.exports.login = function login (req, res, next) {
  varAuthController.login(req.swagger.params, res, next);
};

module.exports.logout = function logout (req, res, next) {
  varAuthController.logout(req.swagger.params, res, next);
};

module.exports.register = function register (req, res, next) {
  varAuthController.register(req.swagger.params, res, next);
};

module.exports.postVerify = function postVerify (req, res, next) {
  varAuthController.postVerify(req, res, next);
};

module.exports.putVerify = function putVerify (req, res, next) {
  varAuthController.putVerify(req, res, next);
};

module.exports.putSuscribed = function putSuscribed (req, res, next) {
  varAuthController.putSuscribed(req, res, next);
};
