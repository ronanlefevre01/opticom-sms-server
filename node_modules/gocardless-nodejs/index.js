'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("./client");
const initialiser = function (token, envrionment, options = {}) {
    return new client_1.GoCardlessClient(token, envrionment, options);
};
module.exports = initialiser;
//# sourceMappingURL=index.js.map