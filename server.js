'use strict';

const deploy = (env) => {
  return new Promise((resolve, reject) => {
    try {
      const fs = require('fs');
      const http = require('http');
      const path = require('path');
      const cors = require('cors');

      const express = require('express');
      const app = express();

      app.use(express.json());

      const domain = process.env.DNS_SUFFIX;
      const subDomain = process.env.SERVICES_PREFIX ? `${process.env.SERVICES_PREFIX}.` : '';

      app.use(cors({
        origin: [`https://${subDomain}${domain}`, 'http://localhost:3000'],
        credentials: true
      }));

      const oasTools = require('oas-tools');
      const jsyaml = require('js-yaml');
      const serverPort = process.env.PORT || 4000;

      const spec = fs.readFileSync(path.join(__dirname, '/api/oas-doc.yaml'), 'utf8');
      const oasDoc = jsyaml.safeLoad(spec);

      const optionsObject = {
        controllers: path.join(__dirname, './controllers'),
        loglevel: env === 'test' ? 'error' : 'info',
        strict: false,
        router: true,
        validator: true
      };

      oasTools.configure(optionsObject);

      oasTools.initialize(oasDoc, app, function () {
        http.createServer(app).listen(serverPort, function () {
          if (env !== 'test') {
            console.log('App running at http://localhost:' + serverPort);
            console.log('________________________________________________________________');
            if (optionsObject.docs !== false) {
              console.log('API docs (Swagger UI) available on http://localhost:' + serverPort + '/docs');
              console.log('________________________________________________________________');
            }
          }
          resolve();
        });
      });
    } catch (err) {
      reject(err);
    }
  });
};

const undeploy = () => {
  process.exit();
};

module.exports = {
  deploy: deploy,
  undeploy: undeploy
};
