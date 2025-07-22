'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoCardlessException = void 0;
class GoCardlessException {
    constructor(response) {
        const { body: { error }, } = response;
        const { message, errors, documentation_url: documentationUrl, type, request_id: requestId, code, } = error;
        this.response = response;
        this.message = message;
        this.errors = errors;
        this.documentationUrl = documentationUrl;
        this.type = type;
        this.requestId = requestId;
        this.code = code;
    }
}
exports.GoCardlessException = GoCardlessException;
//# sourceMappingURL=GoCardlessException.js.map