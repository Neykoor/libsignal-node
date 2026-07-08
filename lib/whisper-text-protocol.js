import $protobuf from 'protobufjs/minimal';
var $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;
var $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});
$root.textsecure = (function () {
    var textsecure = {};
    textsecure.WhisperMessage = (function () {
        function WhisperMessage(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }
        WhisperMessage.prototype.ephemeralKey = $util.newBuffer([]);
        WhisperMessage.prototype.counter = 0;
        WhisperMessage.prototype.previousCounter = 0;
        WhisperMessage.prototype.ciphertext = $util.newBuffer([]);
        WhisperMessage.create = function create(properties) {
            return new WhisperMessage(properties);
        };
        WhisperMessage.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                writer.uint32(10).bytes(message.ephemeralKey);
            if (message.counter != null && message.hasOwnProperty("counter"))
                writer.uint32(16).uint32(message.counter);
            if (message.previousCounter != null && message.hasOwnProperty("previousCounter"))
                writer.uint32(24).uint32(message.previousCounter);
            if (message.ciphertext != null && message.hasOwnProperty("ciphertext"))
                writer.uint32(34).bytes(message.ciphertext);
            return writer;
        };
        WhisperMessage.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };
        WhisperMessage.decode = function decode(reader, length) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.textsecure.WhisperMessage();
            while (reader.pos < end) {
                var tag = reader.uint32();
                switch (tag >>> 3) {
                    case 1:
                        message.ephemeralKey = reader.bytes();
                        break;
                    case 2:
                        message.counter = reader.uint32();
                        break;
                    case 3:
                        message.previousCounter = reader.uint32();
                        break;
                    case 4:
                        message.ciphertext = reader.bytes();
                        break;
                    default:
                        reader.skipType(tag & 7);
                        break;
                }
            }
            return message;
        };
        WhisperMessage.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };
        WhisperMessage.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                if (!(message.ephemeralKey && typeof message.ephemeralKey.length === "number" || $util.isString(message.ephemeralKey)))
                    return "ephemeralKey: buffer expected";
            if (message.counter != null && message.hasOwnProperty("counter"))
                if (!$util.isInteger(message.counter))
                    return "counter: integer expected";
            if (message.previousCounter != null && message.hasOwnProperty("previousCounter"))
                if (!$util.isInteger(message.previousCounter))
                    return "previousCounter: integer expected";
            if (message.ciphertext != null && message.hasOwnProperty("ciphertext"))
                if (!(message.ciphertext && typeof message.ciphertext.length === "number" || $util.isString(message.ciphertext)))
                    return "ciphertext: buffer expected";
            return null;
        };
        WhisperMessage.fromObject = function fromObject(object) {
            if (object instanceof $root.textsecure.WhisperMessage)
                return object;
            var message = new $root.textsecure.WhisperMessage();
            if (object.ephemeralKey != null)
                if (typeof object.ephemeralKey === "string")
                    $util.base64.decode(object.ephemeralKey, message.ephemeralKey = $util.newBuffer($util.base64.length(object.ephemeralKey)), 0);
                else if (object.ephemeralKey.length)
                    message.ephemeralKey = object.ephemeralKey;
            if (object.counter != null)
                message.counter = object.counter >>> 0;
            if (object.previousCounter != null)
                message.previousCounter = object.previousCounter >>> 0;
            if (object.ciphertext != null)
                if (typeof object.ciphertext === "string")
                    $util.base64.decode(object.ciphertext, message.ciphertext = $util.newBuffer($util.base64.length(object.ciphertext)), 0);
                else if (object.ciphertext.length)
                    message.ciphertext = object.ciphertext;
            return message;
        };
        WhisperMessage.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.ephemeralKey = "";
                else {
                    object.ephemeralKey = [];
                    if (options.bytes !== Array)
                        object.ephemeralKey = $util.newBuffer(object.ephemeralKey);
                }
                object.counter = 0;
                object.previousCounter = 0;
                if (options.bytes === String)
                    object.ciphertext = "";
                else {
                    object.ciphertext = [];
                    if (options.bytes !== Array)
                        object.ciphertext = $util.newBuffer(object.ciphertext);
                }
            }
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                object.ephemeralKey = options.bytes === String ? $util.base64.encode(message.ephemeralKey, 0, message.ephemeralKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.ephemeralKey) : message.ephemeralKey;
            if (message.counter != null && message.hasOwnProperty("counter"))
                object.counter = message.counter;
            if (message.previousCounter != null && message.hasOwnProperty("previousCounter"))
                object.previousCounter = message.previousCounter;
            if (message.ciphertext != null && message.hasOwnProperty("ciphertext"))
                object.ciphertext = options.bytes === String ? $util.base64.encode(message.ciphertext, 0, message.ciphertext.length) : options.bytes === Array ? Array.prototype.slice.call(message.ciphertext) : message.ciphertext;
            return object;
        };
        WhisperMessage.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };
        return WhisperMessage;
    })();
    textsecure.PreKeyWhisperMessage = (function () {
        function PreKeyWhisperMessage(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }
        PreKeyWhisperMessage.prototype.registrationId = 0;
        PreKeyWhisperMessage.prototype.preKeyId = 0;
        PreKeyWhisperMessage.prototype.signedPreKeyId = 0;
        PreKeyWhisperMessage.prototype.baseKey = $util.newBuffer([]);
        PreKeyWhisperMessage.prototype.identityKey = $util.newBuffer([]);
        PreKeyWhisperMessage.prototype.message = $util.newBuffer([]);
        PreKeyWhisperMessage.create = function create(properties) {
            return new PreKeyWhisperMessage(properties);
        };
        PreKeyWhisperMessage.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.preKeyId != null && message.hasOwnProperty("preKeyId"))
                writer.uint32(8).uint32(message.preKeyId);
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                writer.uint32(18).bytes(message.baseKey);
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                writer.uint32(26).bytes(message.identityKey);
            if (message.message != null && message.hasOwnProperty("message"))
                writer.uint32(34).bytes(message.message);
            if (message.registrationId != null && message.hasOwnProperty("registrationId"))
                writer.uint32(40).uint32(message.registrationId);
            if (message.signedPreKeyId != null && message.hasOwnProperty("signedPreKeyId"))
                writer.uint32(48).uint32(message.signedPreKeyId);
            return writer;
        };
        PreKeyWhisperMessage.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };
        PreKeyWhisperMessage.decode = function decode(reader, length) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.textsecure.PreKeyWhisperMessage();
            while (reader.pos < end) {
                var tag = reader.uint32();
                switch (tag >>> 3) {
                    case 5:
                        message.registrationId = reader.uint32();
                        break;
                    case 1:
                        message.preKeyId = reader.uint32();
                        break;
                    case 6:
                        message.signedPreKeyId = reader.uint32();
                        break;
                    case 2:
                        message.baseKey = reader.bytes();
                        break;
                    case 3:
                        message.identityKey = reader.bytes();
                        break;
                    case 4:
                        message.message = reader.bytes();
                        break;
                    default:
                        reader.skipType(tag & 7);
                        break;
                }
            }
            return message;
        };
        PreKeyWhisperMessage.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };
        PreKeyWhisperMessage.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.registrationId != null && message.hasOwnProperty("registrationId"))
                if (!$util.isInteger(message.registrationId))
                    return "registrationId: integer expected";
            if (message.preKeyId != null && message.hasOwnProperty("preKeyId"))
                if (!$util.isInteger(message.preKeyId))
                    return "preKeyId: integer expected";
            if (message.signedPreKeyId != null && message.hasOwnProperty("signedPreKeyId"))
                if (!$util.isInteger(message.signedPreKeyId))
                    return "signedPreKeyId: integer expected";
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                if (!(message.baseKey && typeof message.baseKey.length === "number" || $util.isString(message.baseKey)))
                    return "baseKey: buffer expected";
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                if (!(message.identityKey && typeof message.identityKey.length === "number" || $util.isString(message.identityKey)))
                    return "identityKey: buffer expected";
            if (message.message != null && message.hasOwnProperty("message"))
                if (!(message.message && typeof message.message.length === "number" || $util.isString(message.message)))
                    return "message: buffer expected";
            return null;
        };
        PreKeyWhisperMessage.fromObject = function fromObject(object) {
            if (object instanceof $root.textsecure.PreKeyWhisperMessage)
                return object;
            var message = new $root.textsecure.PreKeyWhisperMessage();
            if (object.registrationId != null)
                message.registrationId = object.registrationId >>> 0;
            if (object.preKeyId != null)
                message.preKeyId = object.preKeyId >>> 0;
            if (object.signedPreKeyId != null)
                message.signedPreKeyId = object.signedPreKeyId >>> 0;
            if (object.baseKey != null)
                if (typeof object.baseKey === "string")
                    $util.base64.decode(object.baseKey, message.baseKey = $util.newBuffer($util.base64.length(object.baseKey)), 0);
                else if (object.baseKey.length)
                    message.baseKey = object.baseKey;
            if (object.identityKey != null)
                if (typeof object.identityKey === "string")
                    $util.base64.decode(object.identityKey, message.identityKey = $util.newBuffer($util.base64.length(object.identityKey)), 0);
                else if (object.identityKey.length)
                    message.identityKey = object.identityKey;
            if (object.message != null)
                if (typeof object.message === "string")
                    $util.base64.decode(object.message, message.message = $util.newBuffer($util.base64.length(object.message)), 0);
                else if (object.message.length)
                    message.message = object.message;
            return message;
        };
        PreKeyWhisperMessage.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.preKeyId = 0;
                if (options.bytes === String)
                    object.baseKey = "";
                else {
                    object.baseKey = [];
                    if (options.bytes !== Array)
                        object.baseKey = $util.newBuffer(object.baseKey);
                }
                if (options.bytes === String)
                    object.identityKey = "";
                else {
                    object.identityKey = [];
                    if (options.bytes !== Array)
                        object.identityKey = $util.newBuffer(object.identityKey);
                }
                if (options.bytes === String)
                    object.message = "";
                else {
                    object.message = [];
                    if (options.bytes !== Array)
                        object.message = $util.newBuffer(object.message);
                }
                object.registrationId = 0;
                object.signedPreKeyId = 0;
            }
            if (message.preKeyId != null && message.hasOwnProperty("preKeyId"))
                object.preKeyId = message.preKeyId;
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                object.baseKey = options.bytes === String ? $util.base64.encode(message.baseKey, 0, message.baseKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKey) : message.baseKey;
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                object.identityKey = options.bytes === String ? $util.base64.encode(message.identityKey, 0, message.identityKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.identityKey) : message.identityKey;
            if (message.message != null && message.hasOwnProperty("message"))
                object.message = options.bytes === String ? $util.base64.encode(message.message, 0, message.message.length) : options.bytes === Array ? Array.prototype.slice.call(message.message) : message.message;
            if (message.registrationId != null && message.hasOwnProperty("registrationId"))
                object.registrationId = message.registrationId;
            if (message.signedPreKeyId != null && message.hasOwnProperty("signedPreKeyId"))
                object.signedPreKeyId = message.signedPreKeyId;
            return object;
        };
        PreKeyWhisperMessage.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };
        return PreKeyWhisperMessage;
    })();
    textsecure.KeyExchangeMessage = (function () {
        function KeyExchangeMessage(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }
        KeyExchangeMessage.prototype.id = 0;
        KeyExchangeMessage.prototype.baseKey = $util.newBuffer([]);
        KeyExchangeMessage.prototype.ephemeralKey = $util.newBuffer([]);
        KeyExchangeMessage.prototype.identityKey = $util.newBuffer([]);
        KeyExchangeMessage.prototype.baseKeySignature = $util.newBuffer([]);
        KeyExchangeMessage.create = function create(properties) {
            return new KeyExchangeMessage(properties);
        };
        KeyExchangeMessage.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.id != null && message.hasOwnProperty("id"))
                writer.uint32(8).uint32(message.id);
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                writer.uint32(18).bytes(message.baseKey);
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                writer.uint32(26).bytes(message.ephemeralKey);
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                writer.uint32(34).bytes(message.identityKey);
            if (message.baseKeySignature != null && message.hasOwnProperty("baseKeySignature"))
                writer.uint32(42).bytes(message.baseKeySignature);
            return writer;
        };
        KeyExchangeMessage.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };
        KeyExchangeMessage.decode = function decode(reader, length) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.textsecure.KeyExchangeMessage();
            while (reader.pos < end) {
                var tag = reader.uint32();
                switch (tag >>> 3) {
                    case 1:
                        message.id = reader.uint32();
                        break;
                    case 2:
                        message.baseKey = reader.bytes();
                        break;
                    case 3:
                        message.ephemeralKey = reader.bytes();
                        break;
                    case 4:
                        message.identityKey = reader.bytes();
                        break;
                    case 5:
                        message.baseKeySignature = reader.bytes();
                        break;
                    default:
                        reader.skipType(tag & 7);
                        break;
                }
            }
            return message;
        };
        KeyExchangeMessage.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };
        KeyExchangeMessage.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.id != null && message.hasOwnProperty("id"))
                if (!$util.isInteger(message.id))
                    return "id: integer expected";
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                if (!(message.baseKey && typeof message.baseKey.length === "number" || $util.isString(message.baseKey)))
                    return "baseKey: buffer expected";
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                if (!(message.ephemeralKey && typeof message.ephemeralKey.length === "number" || $util.isString(message.ephemeralKey)))
                    return "ephemeralKey: buffer expected";
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                if (!(message.identityKey && typeof message.identityKey.length === "number" || $util.isString(message.identityKey)))
                    return "identityKey: buffer expected";
            if (message.baseKeySignature != null && message.hasOwnProperty("baseKeySignature"))
                if (!(message.baseKeySignature && typeof message.baseKeySignature.length === "number" || $util.isString(message.baseKeySignature)))
                    return "baseKeySignature: buffer expected";
            return null;
        };
        KeyExchangeMessage.fromObject = function fromObject(object) {
            if (object instanceof $root.textsecure.KeyExchangeMessage)
                return object;
            var message = new $root.textsecure.KeyExchangeMessage();
            if (object.id != null)
                message.id = object.id >>> 0;
            if (object.baseKey != null)
                if (typeof object.baseKey === "string")
                    $util.base64.decode(object.baseKey, message.baseKey = $util.newBuffer($util.base64.length(object.baseKey)), 0);
                else if (object.baseKey.length)
                    message.baseKey = object.baseKey;
            if (object.ephemeralKey != null)
                if (typeof object.ephemeralKey === "string")
                    $util.base64.decode(object.ephemeralKey, message.ephemeralKey = $util.newBuffer($util.base64.length(object.ephemeralKey)), 0);
                else if (object.ephemeralKey.length)
                    message.ephemeralKey = object.ephemeralKey;
            if (object.identityKey != null)
                if (typeof object.identityKey === "string")
                    $util.base64.decode(object.identityKey, message.identityKey = $util.newBuffer($util.base64.length(object.identityKey)), 0);
                else if (object.identityKey.length)
                    message.identityKey = object.identityKey;
            if (object.baseKeySignature != null)
                if (typeof object.baseKeySignature === "string")
                    $util.base64.decode(object.baseKeySignature, message.baseKeySignature = $util.newBuffer($util.base64.length(object.baseKeySignature)), 0);
                else if (object.baseKeySignature.length)
                    message.baseKeySignature = object.baseKeySignature;
            return message;
        };
        KeyExchangeMessage.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.id = 0;
                if (options.bytes === String)
                    object.baseKey = "";
                else {
                    object.baseKey = [];
                    if (options.bytes !== Array)
                        object.baseKey = $util.newBuffer(object.baseKey);
                }
                if (options.bytes === String)
                    object.ephemeralKey = "";
                else {
                    object.ephemeralKey = [];
                    if (options.bytes !== Array)
                        object.ephemeralKey = $util.newBuffer(object.ephemeralKey);
                }
                if (options.bytes === String)
                    object.identityKey = "";
                else {
                    object.identityKey = [];
                    if (options.bytes !== Array)
                        object.identityKey = $util.newBuffer(object.identityKey);
                }
                if (options.bytes === String)
                    object.baseKeySignature = "";
                else {
                    object.baseKeySignature = [];
                    if (options.bytes !== Array)
                        object.baseKeySignature = $util.newBuffer(object.baseKeySignature);
                }
            }
            if (message.id != null && message.hasOwnProperty("id"))
                object.id = message.id;
            if (message.baseKey != null && message.hasOwnProperty("baseKey"))
                object.baseKey = options.bytes === String ? $util.base64.encode(message.baseKey, 0, message.baseKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKey) : message.baseKey;
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey"))
                object.ephemeralKey = options.bytes === String ? $util.base64.encode(message.ephemeralKey, 0, message.ephemeralKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.ephemeralKey) : message.ephemeralKey;
            if (message.identityKey != null && message.hasOwnProperty("identityKey"))
                object.identityKey = options.bytes === String ? $util.base64.encode(message.identityKey, 0, message.identityKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.identityKey) : message.identityKey;
            if (message.baseKeySignature != null && message.hasOwnProperty("baseKeySignature"))
                object.baseKeySignature = options.bytes === String ? $util.base64.encode(message.baseKeySignature, 0, message.baseKeySignature.length) : options.bytes === Array ? Array.prototype.slice.call(message.baseKeySignature) : message.baseKeySignature;
            return object;
        };
        KeyExchangeMessage.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };
        return KeyExchangeMessage;
    })();
    return textsecure;
})();
export default $root;
export const textsecure = $root.textsecure;
