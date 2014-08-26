/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import <Cordova/CDV.h>
#import "SimpleDataTransfer.h"
#import "CDVLocalFilesystem.h"
#import "AGRandomGenerator.h"
#import "CryptoHelper.h"

#import <AssetsLibrary/ALAsset.h>
#import <AssetsLibrary/ALAssetRepresentation.h>
#import <AssetsLibrary/ALAssetsLibrary.h>
#import <CFNetwork/CFNetwork.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface SimpleDataTransfer ()
// Sets the requests headers for the request.
- (void)applyRequestHeaders:(NSDictionary*)headers toRequest:(NSMutableURLRequest*)req;
// Creates a delegate to handle an upload.
- (SimpleDataTransferDelegate*)delegateForUploadCommand:(CDVInvokedUrlCommand*)command encryption:(NSDictionary*)encryption;
// Creates an NSData* for the file for the given upload arguments.
- (void)fileDataForUploadCommand:(CDVInvokedUrlCommand*)command;
@end

// Buffer size to use for streaming uploads.
static const NSUInteger kStreamBufferSize = 32768;

// Magic value within the options dict used to set a cookie.
//NSString* const kOptionsKeyCookieSimple = @"__cookie";
// Form boundary for multi-part requests.
//NSString* const kFormBoundarySimple = @"+++++org.apache.cordova.formBoundary";

// Writes the given data to the stream in a blocking way.
// If successful, returns bytesToWrite.
// If the stream was closed on the other end, returns 0.
// If there was an error, returns -1.
static CFIndex WriteDataToStream(NSData* data, CFWriteStreamRef stream)
{
    UInt8* bytes = (UInt8*)[data bytes];
    long long bytesToWrite = [data length];
    long long totalBytesWritten = 0;
    
    while (totalBytesWritten < bytesToWrite) {
        CFIndex result = CFWriteStreamWrite(stream,
                                            bytes + totalBytesWritten,
                                            bytesToWrite - totalBytesWritten);
        if (result < 0) {
            CFStreamError error = CFWriteStreamGetError(stream);
            NSLog(@"WriteStreamError domain: %ld error: %ld", error.domain, (long)error.error);
            return result;
        } else if (result == 0) {
            return result;
        }
        totalBytesWritten += result;
    }
    
    return totalBytesWritten;
}

@implementation SimpleDataTransfer
@synthesize activeTransfers;

- (void)pluginInitialize {
    activeTransfers = [[NSMutableDictionary alloc] init];
}

- (NSString*)escapePathComponentForUrlString:(NSString*)urlString
{
    NSRange schemeAndHostRange = [urlString rangeOfString:@"://.*?/" options:NSRegularExpressionSearch];
    
    if (schemeAndHostRange.length == 0) {
        return urlString;
    }
    
    NSInteger schemeAndHostEndIndex = NSMaxRange(schemeAndHostRange);
    NSString* schemeAndHost = [urlString substringToIndex:schemeAndHostEndIndex];
    NSString* pathComponent = [urlString substringFromIndex:schemeAndHostEndIndex];
    pathComponent = [pathComponent stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    
    return [schemeAndHost stringByAppendingString:pathComponent];
}

- (void)applyRequestHeaders:(NSDictionary*)headers toRequest:(NSMutableURLRequest*)req
{
    [req setValue:@"XMLHttpRequest" forHTTPHeaderField:@"X-Requested-With"];
    
    NSString* userAgent = [self.commandDelegate userAgent];
    if (userAgent) {
        [req setValue:userAgent forHTTPHeaderField:@"User-Agent"];
    }
    
    for (NSString* headerName in headers) {
        id value = [headers objectForKey:headerName];
        if (!value || (value == [NSNull null])) {
            value = @"null";
        }
        
        // First, remove an existing header if one exists.
        [req setValue:nil forHTTPHeaderField:headerName];
        
        if (![value isKindOfClass:[NSArray class]]) {
            value = [NSArray arrayWithObject:value];
        }
        
        // Then, append all header values.
        for (id __strong subValue in value) {
            // Convert from an NSNumber -> NSString.
            if ([subValue respondsToSelector:@selector(stringValue)]) {
                subValue = [subValue stringValue];
            }
            if ([subValue isKindOfClass:[NSString class]]) {
                [req addValue:subValue forHTTPHeaderField:headerName];
            }
        }
    }
}

- (NSURLRequest*)requestForUploadCommand:(CDVInvokedUrlCommand*)command fileData:(NSData*)fileData encryption:(NSDictionary*)encryption
{
    NSString* file = [command argumentAtIndex:0];
    NSString* url = [command argumentAtIndex:1];
    
    NSDictionary* json = [command argumentAtIndex:2 withDefault:nil];
    NSArray* options = [command argumentAtIndex:3 withDefault:nil];
    
    // Allow alternative http method, default to POST. JS side checks
    // for allowed methods, currently PUT or POST (forces POST for
    // unrecognised values)
    NSString* httpMethod = [options objectAtIndex:0 withDefault:@"POST"];
    BOOL chunkedMode = [[options objectAtIndex:3 withDefault:[NSNumber numberWithBool:YES]] boolValue];
    NSDictionary* headers = [options objectAtIndex:4 withDefault:nil];
    
    CDVPluginResult* result = nil;
    SimpleDataTransferError errorCode = 0;
    
    // NSURL does not accepts URLs with spaces in the path. We escape the path in order
    // to be more lenient.
    NSURL* nsUrl = [NSURL URLWithString:url];
    
    if (!nsUrl) {
        errorCode = INVALID_URL_ERR;
        NSLog(@"SimpleDataTransfer Error: Invalid server URL %@", url);
    } else if (!fileData) {
        errorCode = FILE_NOT_FOUND_ERR;
    }
    
    if (errorCode > 0) {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:errorCode AndSource:file AndTarget:url]];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return nil;
    }
    
    NSMutableURLRequest* req = [NSMutableURLRequest requestWithURL:nsUrl];
    
    [req setHTTPMethod:httpMethod];
    
    // don not set cookies
    [req setHTTPShouldHandleCookies:NO];
    
    NSString* contentType = @"application/json";
    [req setValue:contentType forHTTPHeaderField:@"Content-Type"];
    [self applyRequestHeaders:headers toRequest:req];
    
    DLog(@"SimpleDataTransfer fileData length: %d", [fileData length]);
    
    if(encryption != nil && [encryption objectForKey:@"key"] != nil) {
        DLog(@"SimpleDataTransfer encrypt called");
        
        NSString *key = [encryption objectForKey:@"key"];
        NSString *iv = [encryption objectForKey:@"IV"];
        
        NSData *dataRaw = fileData;
        NSData *keyRaw = [CryptoHelper convertStringToData:key];
        NSData *ivRaw;
        if(iv == nil) {
            ivRaw = [AGRandomGenerator randomBytes:16];
        } else {
            ivRaw = [CryptoHelper convertStringToData:iv];
        }
        
        size_t outLength;
        size_t availableAESSize = dataRaw.length+kCCBlockSizeAES128-(dataRaw.length % kCCBlockSizeAES128);
        NSMutableData *cipherData = [NSMutableData dataWithLength:availableAESSize];
        
        CCCryptorStatus cryptorResult = CCCrypt(kCCEncrypt, // operation
                                                kCCAlgorithmAES, // Algorithm
                                                kCCOptionPKCS7Padding, // options
                                                keyRaw.bytes, // key
                                                keyRaw.length, // keylength
                                                ivRaw.bytes,// iv
                                                dataRaw.bytes, // dataIn
                                                dataRaw.length, // dataInLength,
                                                cipherData.mutableBytes, // dataOut
                                                cipherData.length, // dataOutAvailable
                                                &outLength); // dataOutMoved
        
        if (cryptorResult == kCCSuccess) {
            cipherData.length = outLength;
            
            fileData = cipherData;
        }
    }
    
    NSString *dataAsBase64 = [fileData base64EncodedString];
    
    [json setValue:dataAsBase64 forKey:@"data"];
    
    NSError * err;
    NSData * jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&err];
    NSString * jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    //NSLog(@"SimpleDataTransfer json for upload: %@", jsonString);
    
    NSData* uploadData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    
    long long totalPayloadLength = [uploadData length];
    [req setValue:[[NSNumber numberWithLongLong:totalPayloadLength] stringValue] forHTTPHeaderField:@"Content-Length"];
    
    if (chunkedMode) {
        CFReadStreamRef readStream = NULL;
        CFWriteStreamRef writeStream = NULL;
        CFStreamCreateBoundPair(NULL, &readStream, &writeStream, kStreamBufferSize);
        [req setHTTPBodyStream:CFBridgingRelease(readStream)];
        
        [self.commandDelegate runInBackground:^{
            if (CFWriteStreamOpen(writeStream)) {
                NSData* chunks[] = {uploadData};
                int numChunks = sizeof(chunks) / sizeof(chunks[0]);
                
                for (int i = 0; i < numChunks; ++i) {
                    CFIndex result = WriteDataToStream(chunks[i], writeStream);
                    if (result <= 0) {
                        break;
                    }
                }
            } else {
                NSLog(@"SimpleDataTransfer: Failed to open writeStream");
            }
            CFWriteStreamClose(writeStream);
            CFRelease(writeStream);
        }];
    } else {
        [req setHTTPBody:uploadData];
    }
    return req;
}

- (SimpleDataTransferDelegate*)delegateForUploadCommand:(CDVInvokedUrlCommand*)command encryption:(NSDictionary*)encryption
{
    NSString* file = [command.arguments objectAtIndex:0];
    NSString* url = [command.arguments objectAtIndex:1];
    
    NSArray* options = [command argumentAtIndex:3 withDefault:nil];
    
    BOOL trustAllHosts = [[options objectAtIndex:2 withDefault:[NSNumber numberWithBool:NO]] boolValue]; // allow self-signed certs
    NSString* objectId = [options objectAtIndex:1];
    
    SimpleDataTransferDelegate* delegate = [[SimpleDataTransferDelegate alloc] init];
    
    delegate.command = self;
    delegate.callbackId = command.callbackId;
    delegate.direction = CDV_TRANSFER_UPLOAD;
    delegate.objectId = objectId;
    delegate.source = file;
    delegate.target = url;
    delegate.trustAllHosts = trustAllHosts;
    delegate.filePlugin = [self.commandDelegate getCommandInstance:@"File"];
    delegate.encryption = encryption;
    
    return delegate;
}

- (void)fileDataForUploadCommand:(CDVInvokedUrlCommand*)command
{
    NSString* file = (NSString*)[command.arguments objectAtIndex:0];
    NSString* url = [command.arguments objectAtIndex:1];
    NSError* __autoreleasing err = nil;
    
    CDVFilesystemURL *sourceURL = [CDVFilesystemURL fileSystemURLWithString:file];
    NSObject<CDVFileSystem> *fs;
    if (sourceURL) {
        // Try to get a CDVFileSystem which will handle this file.
        // This requires talking to the current CDVFile plugin.
        fs = [[self.commandDelegate getCommandInstance:@"File"] filesystemForURL:sourceURL];
    }
    if (fs) {
        [fs readFileAtURL:sourceURL start:0 end:-1 callback:^(NSData *fileData, NSString *mimeType, CDVFileError err) {
            if (err) {
                // We couldn't find the asset.  Send the appropriate error.
                CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:NOT_FOUND_ERR AndSource:file AndTarget:url]];
                [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            }  else {
                [self uploadData:fileData command:command];
            }
        }];
        return;
    } else {
        // Extract the path part out of a file: URL.
        NSString* filePath = [file hasPrefix:@"/"] ? [file copy] : [(NSURL *)[NSURL URLWithString:file] path];
        if (filePath == nil) {
            // We couldn't find the asset.  Send the appropriate error.
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:NOT_FOUND_ERR AndSource:file AndTarget:url]];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            return;
        }
        
        // Memory map the file so that it can be read efficiently even if it is large.
        NSData* fileData = [NSData dataWithContentsOfFile:filePath options:NSDataReadingMappedIfSafe error:&err];
        
        if (err != nil) {
            NSLog(@"Error opening file %@: %@", file, err);
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:NOT_FOUND_ERR AndSource:file AndTarget:url]];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        } else {
            [self uploadData:fileData command:command];
        }
    }
}

- (void)uploadFileAsJson:(CDVInvokedUrlCommand*)command
{
    // fileData and req are split into helper functions to ease the unit testing of delegateForUpload.
    // First, get the file data.  This method will call `uploadData:command`.
    [self fileDataForUploadCommand:command];
}

- (void)uploadData:(NSData*)fileData command:(CDVInvokedUrlCommand*)command
{
    
    NSDictionary* encryption = [command argumentAtIndex:4 withDefault:nil];
    if(encryption != nil && [encryption objectForKey:@"key"] != nil) {
        NSString *iv = [encryption objectForKey:@"IV"];
        
        NSData *ivRaw;
        if(iv == nil) {
            ivRaw = [AGRandomGenerator randomBytes:16];
            [encryption setValue:[CryptoHelper convertDataToString:ivRaw] forKey:@"IV"];
        }
    }
    
    NSURLRequest* req = [self requestForUploadCommand:command fileData:fileData encryption:encryption];
    
    if (req == nil) {
        return;
    }
    SimpleDataTransferDelegate* delegate = [self delegateForUploadCommand:command encryption:encryption];
    delegate.connection = [[NSURLConnection alloc] initWithRequest:req delegate:delegate startImmediately:NO];
    if (self.queue == nil) {
        self.queue = [[NSOperationQueue alloc] init];
    }
    [delegate.connection setDelegateQueue:self.queue];
    
    // sets a background task ID for the transfer object.
    delegate.backgroundTaskID = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
        [delegate cancelTransfer:delegate.connection];
    }];
    
    @synchronized (activeTransfers) {
        activeTransfers[delegate.objectId] = delegate;
    }
    [delegate.connection start];
}

- (void)abort:(CDVInvokedUrlCommand*)command
{
    NSString* objectId = [command.arguments objectAtIndex:0];
    
    @synchronized (activeTransfers) {
        SimpleDataTransferDelegate* delegate = activeTransfers[objectId];
        if (delegate != nil) {
            [delegate cancelTransfer:delegate.connection];
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:CONNECTION_ABORTED AndSource:delegate.source AndTarget:delegate.target]];
            [self.commandDelegate sendPluginResult:result callbackId:delegate.callbackId];
        }
    }
}

- (void)downloadFileAsJson:(CDVInvokedUrlCommand*)command
{
    DLog(@"SimpleDataTransfer downloading file...");
    NSString* file = [command.arguments objectAtIndex:0];
    NSString* url = [command.arguments objectAtIndex:1];
    
    NSArray* options = [command argumentAtIndex:2 withDefault:nil];
    NSDictionary* encryption = [command argumentAtIndex:3 withDefault:nil];
    
    BOOL trustAllHosts = [[options objectAtIndex:0 withDefault:[NSNumber numberWithBool:NO]] boolValue]; // allow self-signed certs
    NSString* objectId = [options objectAtIndex:1];
    NSDictionary* headers = [options objectAtIndex:2 withDefault:nil];
    
    CDVPluginResult* result = nil;
    SimpleDataTransferError errorCode = 0;
    
    NSURL* targetURL = [NSURL URLWithString:file];
    NSURL* sourceURL = [NSURL URLWithString:url];
    
    CDVFilesystemURL *fsURL = [CDVFilesystemURL fileSystemURLWithString:file];
    if (!fsURL) {
        errorCode = FILE_NOT_FOUND_ERR;
        NSLog(@"File Transfer Error: Invalid file path or URL %@", file);
    }
    
    if (errorCode > 0) {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:errorCode AndSource:file AndTarget:url]];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSLog(@"requestWithURL %@", sourceURL);
    NSMutableURLRequest* req = [NSMutableURLRequest requestWithURL:sourceURL];
    [self applyRequestHeaders:headers toRequest:req];
    
    SimpleDataTransferDelegate* delegate = [[SimpleDataTransferDelegate alloc] init];
    delegate.command = self;
    delegate.direction = CDV_TRANSFER_DOWNLOAD;
    delegate.callbackId = command.callbackId;
    delegate.objectId = objectId;
    delegate.source = file;
    delegate.target = [targetURL absoluteString];
    delegate.targetURL = targetURL;
    delegate.trustAllHosts = trustAllHosts;
    delegate.filePlugin = [self.commandDelegate getCommandInstance:@"File"];
    delegate.encryption = encryption;
    delegate.backgroundTaskID = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
        [delegate cancelTransfer:delegate.connection];
    }];
    
    delegate.connection = [[NSURLConnection alloc] initWithRequest:req delegate:delegate startImmediately:NO];
    
    if (self.queue == nil) {
        self.queue = [[NSOperationQueue alloc] init];
    }
    [delegate.connection setDelegateQueue:self.queue];
    
    @synchronized (activeTransfers) {
        activeTransfers[delegate.objectId] = delegate;
    }
    // Downloads can take time
    // sending this to a new thread calling the download_async method
    dispatch_async(
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, (unsigned long)NULL),
                   ^(void) { [delegate.connection start];}
                   );
}

- (NSMutableDictionary*)createFileTransferError:(int)code AndSource:(NSString*)source AndTarget:(NSString*)target
{
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithCapacity:3];
    
    [result setObject:[NSNumber numberWithInt:code] forKey:@"code"];
    if (source != nil) {
        [result setObject:source forKey:@"source"];
    }
    if (target != nil) {
        [result setObject:target forKey:@"target"];
    }
    NSLog(@"FileTransferError %@", result);
    
    return result;
}

- (NSMutableDictionary*)createFileTransferError:(int)code
                                      AndSource:(NSString*)source
                                      AndTarget:(NSString*)target
                                  AndHttpStatus:(int)httpStatus
                                        AndBody:(NSString*)body
{
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithCapacity:5];
    
    [result setObject:[NSNumber numberWithInt:code] forKey:@"code"];
    if (source != nil) {
        [result setObject:source forKey:@"source"];
    }
    if (target != nil) {
        [result setObject:target forKey:@"target"];
    }
    [result setObject:[NSNumber numberWithInt:httpStatus] forKey:@"http_status"];
    if (body != nil) {
        [result setObject:body forKey:@"body"];
    }
    NSLog(@"FileTransferError %@", result);
    
    return result;
}

- (void)onReset {
    @synchronized (activeTransfers) {
        while ([activeTransfers count] > 0) {
            SimpleDataTransferDelegate* delegate = [activeTransfers allValues][0];
            [delegate cancelTransfer:delegate.connection];
        }
    }
}
@end

@interface SimpleDataTransferEntityLengthRequest : NSObject {
    NSURLConnection* _connection;
    SimpleDataTransferDelegate* __weak _originalDelegate;
}

- (SimpleDataTransferEntityLengthRequest*)initWithOriginalRequest:(NSURLRequest*)originalRequest andDelegate:(SimpleDataTransferDelegate*)originalDelegate;

@end

@implementation SimpleDataTransferEntityLengthRequest

- (SimpleDataTransferEntityLengthRequest*)initWithOriginalRequest:(NSURLRequest*)originalRequest andDelegate:(SimpleDataTransferDelegate*)originalDelegate
{
    if (self) {
        DLog(@"Requesting entity length for GZIPped content...");
        
        NSMutableURLRequest* req = [originalRequest mutableCopy];
        [req setHTTPMethod:@"HEAD"];
        [req setValue:@"identity" forHTTPHeaderField:@"Accept-Encoding"];
        
        _originalDelegate = originalDelegate;
        _connection = [NSURLConnection connectionWithRequest:req delegate:self];
    }
    return self;
}

- (void)connection:(NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)response
{
    DLog(@"HEAD request returned; content-length is %lld", [response expectedContentLength]);
    [_originalDelegate updateBytesExpected:[response expectedContentLength]];
}

- (void)connection:(NSURLConnection*)connection didReceiveData:(NSData*)data
{}

- (void)connectionDidFinishLoading:(NSURLConnection*)connection
{}

@end

@implementation SimpleDataTransferDelegate

@synthesize callbackId, connection = _connection, source, target, responseData, responseHeaders, command, bytesTransfered, bytesExpected, direction, responseCode, objectId, targetFileHandle, filePlugin, encryption;

- (void)connectionDidFinishLoading:(NSURLConnection*)connection
{
    NSString* uploadResponse = nil;
    NSString* downloadResponse = nil;
    NSMutableDictionary* uploadResult;
    CDVPluginResult* result = nil;
    
    NSLog(@"File Transfer Finished with response code %d", self.responseCode);
    
    if (self.direction == CDV_TRANSFER_UPLOAD) {
        uploadResponse = [[NSString alloc] initWithData:self.responseData encoding:NSUTF8StringEncoding];
        
        if ((self.responseCode >= 200) && (self.responseCode < 300)) {
            // create dictionary to return FileUploadResult object
            uploadResult = [NSMutableDictionary dictionaryWithCapacity:3];
            if (uploadResponse != nil) {
                [uploadResult setObject:uploadResponse forKey:@"response"];
                [uploadResult setObject:self.responseHeaders forKey:@"headers"];
            }
            [uploadResult setObject:[NSNumber numberWithLongLong:self.bytesTransfered] forKey:@"bytesSent"];
            [uploadResult setObject:[NSNumber numberWithInt:self.responseCode] forKey:@"responseCode"];
            
            if(self.encryption != nil) {
                [uploadResult setObject:encryption forKey:@"encryption"];
            }
            
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:uploadResult];
        } else {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[command createFileTransferError:CONNECTION_ERR AndSource:source AndTarget:target AndHttpStatus:self.responseCode AndBody:uploadResponse]];
        }
    }
    if (self.direction == CDV_TRANSFER_DOWNLOAD) {
        if (self.targetFileHandle) {
            
            NSError* error;
            NSDictionary* jsonStatic = [NSJSONSerialization JSONObjectWithData:self.responseData options:kNilOptions error:&error];
            NSMutableDictionary *json = [jsonStatic mutableCopy];
            
            if([json objectForKey:@"data"] != nil) {
                
                NSData* fileData = [NSData dataFromBase64String:[json objectForKey:@"data"]];
                if(self.encryption != nil && [self.encryption objectForKey:@"key"] != nil) {
                    NSString *key = [self.encryption objectForKey:@"key"];
                    NSString *iv = [self.encryption objectForKey:@"IV"];
                    
                    NSData *keyRaw = [CryptoHelper convertStringToData:key];
                    NSData *ivRaw = [CryptoHelper convertStringToData:iv];
                    
                    size_t outLength;
                    size_t availableAESSize = fileData.length-(fileData.length % kCCBlockSizeAES128);
                    NSMutableData *cipherData = [NSMutableData dataWithLength:availableAESSize];
                    
                    CCCryptorStatus cryptorResult = CCCrypt(kCCDecrypt, // operation
                                                            kCCAlgorithmAES, // Algorithm
                                                            kCCOptionPKCS7Padding, // options
                                                            keyRaw.bytes, // key
                                                            keyRaw.length, // keylength
                                                            ivRaw.bytes,// iv
                                                            fileData.bytes, // dataIn
                                                            fileData.length, // dataInLength,
                                                            cipherData.mutableBytes, // dataOut
                                                            cipherData.length, // dataOutAvailable
                                                            &outLength); // dataOutMoved
                    
                    
                    if (cryptorResult == kCCSuccess) {
                        cipherData.length = outLength;
                        fileData = cipherData;
                    }
                }
                
                NSString* md5 = [CryptoHelper MD5StringFromData:fileData];
                [json setObject:md5 forKey:@"hash"];
                
                [json removeObjectForKey:@"data"];
                
                [self.targetFileHandle writeData:fileData];
            }
            
            [self.targetFileHandle closeFile];
            self.targetFileHandle = nil;
            DLog(@"File Transfer Download success");
            
            
            NSMutableDictionary* downloadResult = [NSMutableDictionary dictionaryWithCapacity:5];
            
            [downloadResult setObject:[NSNumber numberWithLong:self.bytesTransfered] forKey:@"bytesReceived"];
            [downloadResult setObject:[NSNumber numberWithLong:self.responseCode] forKey:@"responseCode"];
            [downloadResult setObject:self.objectId forKey:@"objectId"];
            
            [downloadResult setObject:[self.filePlugin makeEntryForURL:self.targetURL] forKey:@"file"];
            [downloadResult setObject:json forKey:@"json"];
            
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:downloadResult];
        } else {
            downloadResponse = [[NSString alloc] initWithData:self.responseData encoding:NSUTF8StringEncoding];
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[command createFileTransferError:CONNECTION_ERR AndSource:source AndTarget:target AndHttpStatus:self.responseCode AndBody:downloadResponse]];
        }
    }
    
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
    
    // remove connection for activeTransfers
    @synchronized (command.activeTransfers) {
        [command.activeTransfers removeObjectForKey:objectId];
        // remove background id task in case our upload was done in the background
        [[UIApplication sharedApplication] endBackgroundTask:self.backgroundTaskID];
        self.backgroundTaskID = UIBackgroundTaskInvalid;
    }
}

- (void)removeTargetFile
{
    NSFileManager* fileMgr = [NSFileManager defaultManager];
    
    [fileMgr removeItemAtPath:[self targetFilePath] error:nil];
}

- (void)cancelTransfer:(NSURLConnection*)connection
{
    [connection cancel];
    @synchronized (self.command.activeTransfers) {
        SimpleDataTransferDelegate* delegate = self.command.activeTransfers[self.objectId];
        [self.command.activeTransfers removeObjectForKey:self.objectId];
        [[UIApplication sharedApplication] endBackgroundTask:delegate.backgroundTaskID];
        delegate.backgroundTaskID = UIBackgroundTaskInvalid;
    }
    
    [self removeTargetFile];
}

- (void)cancelTransferWithError:(NSURLConnection*)connection errorMessage:(NSString*)errorMessage
{
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_IO_EXCEPTION messageAsDictionary:[self.command createFileTransferError:FILE_NOT_FOUND_ERR AndSource:self.source AndTarget:self.target AndHttpStatus:self.responseCode AndBody:errorMessage]];
    
    NSLog(@"File Transfer Error: %@", errorMessage);
    [self cancelTransfer:connection];
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
}

- (NSString *)targetFilePath
{
    NSString *path = nil;
    CDVFilesystemURL *sourceURL = [CDVFilesystemURL fileSystemURLWithString:self.target];
    if (sourceURL && sourceURL.fileSystemName != nil) {
        // This requires talking to the current CDVFile plugin
        NSObject<CDVFileSystem> *fs = [self.filePlugin filesystemForURL:sourceURL];
        path = [fs filesystemPathForURL:sourceURL];
    } else {
        // Extract the path part out of a file: URL.
        path = [self.target hasPrefix:@"/"] ? [self.target copy] : [(NSURL *)[NSURL URLWithString:self.target] path];
    }
    return path;
}

- (void)connection:(NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)response
{
    NSError* __autoreleasing error = nil;
    
    self.mimeType = [response MIMEType];
    self.targetFileHandle = nil;
    
    // required for iOS 4.3, for some reason; response is
    // a plain NSURLResponse, not the HTTP subclass
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
        
        self.responseCode = [httpResponse statusCode];
        self.bytesExpected = [response expectedContentLength];
        self.responseHeaders = [httpResponse allHeaderFields];
        if ((self.direction == CDV_TRANSFER_DOWNLOAD) && (self.responseCode == 200) && (self.bytesExpected == NSURLResponseUnknownLength)) {
            // Kick off HEAD request to server to get real length
            // bytesExpected will be updated when that response is returned
            self.entityLengthRequest = [[SimpleDataTransferEntityLengthRequest alloc] initWithOriginalRequest:connection.currentRequest andDelegate:self];
        }
    } else if ([response.URL isFileURL]) {
        NSDictionary* attr = [[NSFileManager defaultManager] attributesOfItemAtPath:[response.URL path] error:nil];
        self.responseCode = 200;
        self.bytesExpected = [attr[NSFileSize] longLongValue];
    } else {
        self.responseCode = 200;
        self.bytesExpected = NSURLResponseUnknownLength;
    }
    if ((self.direction == CDV_TRANSFER_DOWNLOAD) && (self.responseCode >= 200) && (self.responseCode < 300)) {
        // Download response is okay; begin streaming output to file
        NSString *filePath = [self targetFilePath];
        if (filePath == nil) {
            // We couldn't find the asset.  Send the appropriate error.
            [self cancelTransferWithError:connection errorMessage:[NSString stringWithFormat:@"Could not create target file"]];
            return;
        }
        
        NSString* parentPath = [filePath stringByDeletingLastPathComponent];
        
        // create parent directories if needed
        if ([[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error] == NO) {
            if (error) {
                [self cancelTransferWithError:connection errorMessage:[NSString stringWithFormat:@"Could not create path to save downloaded file: %@", [error localizedDescription]]];
            } else {
                [self cancelTransferWithError:connection errorMessage:@"Could not create path to save downloaded file"];
            }
            return;
        }
        // create target file
        if ([[NSFileManager defaultManager] createFileAtPath:filePath contents:nil attributes:nil] == NO) {
            [self cancelTransferWithError:connection errorMessage:@"Could not create target file"];
            return;
        }
        // open target file for writing
        self.targetFileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
        if (self.targetFileHandle == nil) {
            [self cancelTransferWithError:connection errorMessage:@"Could not open target file for writing"];
        }
        DLog(@"Streaming to file %@", filePath);
    }
}

- (void)connection:(NSURLConnection*)connection didFailWithError:(NSError*)error
{
    NSString* body = [[NSString alloc] initWithData:self.responseData encoding:NSUTF8StringEncoding];
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[command createFileTransferError:CONNECTION_ERR AndSource:source AndTarget:target AndHttpStatus:self.responseCode AndBody:body]];
    
    NSLog(@"File Transfer Error: %@", [error localizedDescription]);
    
    [self cancelTransfer:connection];
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
}

- (void)connection:(NSURLConnection*)connection didReceiveData:(NSData*)data
{
    self.bytesTransfered += data.length;
    if (self.targetFileHandle) {
        //[self.targetFileHandle writeData:data];
        [self.responseData appendData:data];
    } else {
        [self.responseData appendData:data];
    }
    [self updateProgress];
}

- (void)updateBytesExpected:(long long)newBytesExpected
{
    DLog(@"Updating bytesExpected to %lld", newBytesExpected);
    self.bytesExpected = newBytesExpected;
    [self updateProgress];
}

- (void)updateProgress
{
    if (self.direction == CDV_TRANSFER_DOWNLOAD) {
        BOOL lengthComputable = (self.bytesExpected != NSURLResponseUnknownLength);
        // If the response is GZipped, and we have an outstanding HEAD request to get
        // the length, then hold off on sending progress events.
        if (!lengthComputable && (self.entityLengthRequest != nil)) {
            return;
        }
        NSMutableDictionary* downloadProgress = [NSMutableDictionary dictionaryWithCapacity:3];
        [downloadProgress setObject:[NSNumber numberWithBool:lengthComputable] forKey:@"lengthComputable"];
        [downloadProgress setObject:[NSNumber numberWithLongLong:self.bytesTransfered] forKey:@"loaded"];
        [downloadProgress setObject:[NSNumber numberWithLongLong:self.bytesExpected] forKey:@"total"];
        CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:downloadProgress];
        [result setKeepCallbackAsBool:true];
        [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
    }
}

- (void)connection:(NSURLConnection*)connection didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite
{
    if (self.direction == CDV_TRANSFER_UPLOAD) {
        NSMutableDictionary* uploadProgress = [NSMutableDictionary dictionaryWithCapacity:3];
        
        [uploadProgress setObject:[NSNumber numberWithBool:true] forKey:@"lengthComputable"];
        [uploadProgress setObject:[NSNumber numberWithLongLong:totalBytesWritten] forKey:@"loaded"];
        [uploadProgress setObject:[NSNumber numberWithLongLong:totalBytesExpectedToWrite] forKey:@"total"];
        CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:uploadProgress];
        [result setKeepCallbackAsBool:true];
        [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
    }
    self.bytesTransfered = totalBytesWritten;
}

// for self signed certificates
- (void)connection:(NSURLConnection*)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge*)challenge
{
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        if (self.trustAllHosts) {
            NSURLCredential* credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
        }
        [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    } else {
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

- (id)init
{
    if ((self = [super init])) {
        self.responseData = [NSMutableData data];
        self.targetFileHandle = nil;
    }
    return self;
}

@end
