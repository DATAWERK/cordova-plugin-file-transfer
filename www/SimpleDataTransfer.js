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

SimpleDataTransfer.prototype.uploadFileAsJson = function(file, url, successCallback, errorCallback, json, options, encryption) {
    argscheck.checkArgs('ssFFOAO*', 'SimpleDataTransfer.uploadFileAsJson', arguments);

	// add custom id
	options[1] = this._id;
	
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

    exec(win, fail, 'SimpleDataTransfer', 'uploadFileAsJson', [file, url, json, options, encryption]);
};

SimpleDataTransfer.prototype.downloadFileAsJson = function(file, url, successCallback, errorCallback, options, encryption) {
    argscheck.checkArgs('ssFFAO*', 'SimpleDataTransfer.downloadFileAsJson', arguments);
    var self = this;

	// add custom id
	options[1] = this._id;

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

    exec(win, fail, 'SimpleDataTransfer', 'downloadFileAsJson', [file, url, options, encryption]);
};

/**
 * Aborts the ongoing file transfer on this object. The original error
 * callback for the file transfer will be called if necessary.
 */
SimpleDataTransfer.prototype.abort = function() {
    exec(null, null, 'SimpleDataTransfer', 'abort', [this._id]);
};

module.exports = SimpleDataTransfer;