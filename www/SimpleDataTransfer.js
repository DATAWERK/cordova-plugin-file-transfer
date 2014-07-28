var argscheck = require('cordova/argscheck'),
    exec = require('cordova/exec');

var SimpleDataProgressEvent = (function() {
	return function SimpleDataProgressEvent(type, dict) {
		this.type = type;
		this.bubbles = false;
		this.cancelBubble = false;
		this.cancelable = false;
		this.loaded = dict && dict.loaded ? dict.loaded : 0;
		this.total = dict && dict.total ? dict.total : 0;
		this.target = dict && dict.target ? dict.target : null;
	};
})();

function simpleDataError(e) {
	var code = 0;
	var url = 0;
	var http_status = 0;
	var body = 0;
	var exception = 0;

	if(typeof e.code != "undefined") {
		code = e.code
	}

	if(typeof e.url != "undefined") {
		url = e.url
	}
	
	if(typeof e.http_status != "undefined") {
		http_status = e.http_status
	}
	
	if(typeof e.body != "undefined") {
		body = e.body
	}
	
	if(typeof e.exception != "undefined") {
		exception = e.exception
	}
	
	var error = {code: code, url: url, http_status: http_status, body: body, exception: exception};
	
    return error;    
};

function newSimpleDataProgressEvent(result) {
    var pe = new SimpleDataProgressEvent();
    pe.loaded = result.loaded;
    pe.total = result.total;
    return pe;
}

var idCounter = 0;

/**
 * SimpleDataTransfer uploads a file to a remote server.
 * @constructor
 */
var SimpleDataTransfer = function() {
    this._id = ++idCounter;
    this.onprogress = null; // optional callback
};

/**
* Given an absolute file path, uploads a file on the device to a remote server
* using a multipart HTTP request.
* @param url {String}           	 URL of the server to send the data
* @param data {String}             	 DATA to send
* @param successCallback (Function}  Callback to be invoked when upload has completed
* @param errorCallback {Function}    Callback to be invoked upon error
* @param options {Object} 			 Optional parameters such mimetype or headers
*/
SimpleDataTransfer.prototype.upload = function(url, data, successCallback, errorCallback, options) {
    argscheck.checkArgs('ssFFO*', 'SimpleDataTransfer.upload', arguments);

    // check for options
    var mimeType = null;
    var httpMethod = null;
    var trustAllHosts = false;
    var chunkedMode = true;
    var headers = null;
        
    if (options) {
        mimeType = options.mimeType;
        httpMethod = options.httpMethod || "POST";
        if (httpMethod.toUpperCase() == "PUT"){
            httpMethod = "PUT";
        } else {
            httpMethod = "POST";
        }
        if (options.trustAllHosts !== null || typeof options.trustAllHosts != "undefined") {
            trustAllHosts = options.trustAllHosts;
        }
        if (options.chunkedMode !== null || typeof options.chunkedMode != "undefined") {
            chunkedMode = options.chunkedMode;
        }
        headers = options.headers;
    }

    var fail = errorCallback && function(e) {
    	var error = simpleDataError(e);
    	errorCallback(error);
    };

    var self = this;
    var win = function(result) {
    	if (typeof result.loaded != "undefined" && typeof result.total != "undefined") {
            if (self.onprogress) {
                self.onprogress(newSimpleDataProgressEvent(result));
            }
        } else {
            successCallback && successCallback(result);
        }
    };
    exec(win, fail, 'SimpleDataTransfer', 'upload', [url, data, mimeType, httpMethod, this._id, trustAllHosts, chunkedMode, headers]);
};

/**
 * Downloads a file form a given URL and saves it to the specified directory.
 * @param url {String}          	  URL of the server to receive the file
 * @param successCallback (Function}  Callback to be invoked when upload has completed
 * @param errorCallback {Function}    Callback to be invoked upon error
 * @param options {Object} 			  Optional parameters such as headers
 */
SimpleDataTransfer.prototype.download = function(url, successCallback, errorCallback, options) {
    argscheck.checkArgs('sFFO*', 'SimpleDataTransfer.download', arguments);
    var self = this;

    var trustAllHosts = false;
    var headers = null;
    if (options) {
    	if (options.trustAllHosts !== null || typeof options.trustAllHosts != "undefined") {
            trustAllHosts = options.trustAllHosts;
        }
        headers = options.headers || null;
    }

    var win = function(result) {
    	if (typeof result.loaded != "undefined" && typeof result.total != "undefined") {
            if (self.onprogress) {
                return self.onprogress(newSimpleDataProgressEvent(result));
            }
        } else if (successCallback) {
            successCallback(result);
        }
    };

    var fail = errorCallback && function(e) {
        var error = simpleDataError(e);
        errorCallback(error);
    };

    exec(win, fail, 'SimpleDataTransfer', 'download', [url, trustAllHosts, this._id, headers]);
};

/**
 * Aborts the ongoing file transfer on this object. The original error
 * callback for the file transfer will be called if necessary.
 */
SimpleDataTransfer.prototype.abort = function() {
    exec(null, null, 'SimpleDataTransfer', 'abort', [this._id]);
};

module.exports = SimpleDataTransfer;