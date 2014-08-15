package de.datawerk.cordova.plugin.data;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaResourceApi;
import org.apache.cordova.CordovaResourceApi.OpenForReadResult;
import org.apache.cordova.PluginResult;
import org.apache.cordova.file.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.net.Uri;
import android.util.Base64;
import android.util.Log;
import android.webkit.CookieManager;

import com.neilalexander.jnacl.NaCl;

public class SimpleDataTransfer extends CordovaPlugin {

    private static final String LOG_TAG = "SimpleDataTransfer";
    
    public static int FILE_NOT_FOUND_ERR = 1;
    public static int INVALID_URL_ERR = 2;
    public static int CONNECTION_ERR = 3;
    public static int ABORTED_ERR = 4;

    private static HashMap<String, RequestContext> activeRequests = new HashMap<String, RequestContext>();
    private static final int MAX_BUFFER_SIZE = 16 * 1024;

    private static final class RequestContext {
        String source;
        File targetFile;
        CallbackContext callbackContext;
        HttpURLConnection connection;
        boolean aborted;
        RequestContext(String source, CallbackContext callbackContext) {
            this.source = source;
            this.callbackContext = callbackContext;
        }
        void sendPluginResult(PluginResult pluginResult) {
            synchronized (this) {
                if (!aborted) {
                    callbackContext.sendPluginResult(pluginResult);
                }
            }
        }
    }

    /**
     * Adds an interface method to an InputStream to return the number of bytes
     * read from the raw stream. This is used to track total progress against
     * the HTTP Content-Length header value from the server.
     */
    private static abstract class TrackingInputStream extends FilterInputStream {
      public TrackingInputStream(final InputStream in) {
        super(in);
      }
        public abstract long getTotalRawBytesRead();
  }

    private static class ExposedGZIPInputStream extends GZIPInputStream {
      public ExposedGZIPInputStream(final InputStream in) throws IOException {
        super(in);
      }
      public Inflater getInflater() {
        return inf;
      }
  }

    /**
     * Provides raw bytes-read tracking for a GZIP input stream. Reports the
     * total number of compressed bytes read from the input, rather than the
     * number of uncompressed bytes.
     */
    private static class TrackingGZIPInputStream extends TrackingInputStream {
      private ExposedGZIPInputStream gzin;
      public TrackingGZIPInputStream(final ExposedGZIPInputStream gzin) throws IOException {
        super(gzin);
        this.gzin = gzin;
      }
      public long getTotalRawBytesRead() {
        return gzin.getInflater().getBytesRead();
      }
  }

    /**
     * Provides simple total-bytes-read tracking for an existing InputStream
     */
    private static class SimpleTrackingInputStream extends TrackingInputStream {
        private long bytesRead = 0;
        public SimpleTrackingInputStream(InputStream stream) {
            super(stream);
        }

        private int updateBytesRead(int newBytesRead) {
          if (newBytesRead != -1) {
            bytesRead += newBytesRead;
          }
          return newBytesRead;
        }

        @Override
        public int read() throws IOException {
            return updateBytesRead(super.read());
        }

        // Note: FilterInputStream delegates read(byte[] bytes) to the below method,
        // so we don't override it or else double count (CB-5631).
        @Override
        public int read(byte[] bytes, int offset, int count) throws IOException {
            return updateBytesRead(super.read(bytes, offset, count));
        }

        public long getTotalRawBytesRead() {
          return bytesRead;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (action.equals("upload") || action.equals("download")) {
            String url = args.getString(0);
            
            if (action.equals("upload")) {
                upload(url, args, callbackContext);
            } else {
                download(url, args, callbackContext);
            }
            return true;
        } else if (action.equals("uploadFileAsJson") || action.equals("downloadFileAsJson")) {
        	if (action.equals("uploadFileAsJson")) {
        		uploadFileAsJson(args, callbackContext);
            } else {
            	downloadFileAsJson(args, callbackContext);
            }
            return true;
        } 
        
        else if (action.equals("abort")) {
            String objectId = args.getString(0);
            abort(objectId);
            callbackContext.success();
            return true;
        }
        return false;
    }

    private static void addHeadersToRequest(URLConnection connection, JSONObject headers) {
        try {
            for (Iterator<?> iter = headers.keys(); iter.hasNext(); ) {
                String headerKey = iter.next().toString();
                JSONArray headerValues = headers.optJSONArray(headerKey);
                if (headerValues == null) {
                    headerValues = new JSONArray();
                    headerValues.put(headers.getString(headerKey));
                }
                connection.setRequestProperty(headerKey, headerValues.getString(0));
                for (int i = 1; i < headerValues.length(); ++i) {
                    connection.addRequestProperty(headerKey, headerValues.getString(i));
                }
            }
        } catch (JSONException e1) {
          // No headers to be manipulated!
        }
    }

    private void uploadFileAsJson(JSONArray args, CallbackContext callbackContext) throws JSONException {
    	final String file = args.getString(0);
    	final String url = args.getString(1);
        
        final JSONObject json = args.optJSONObject(2);
        final JSONArray options = args.optJSONArray(3);
        final JSONObject encryption = args.optJSONObject(4);
        
        // Setup the options
        final String httpMethod = getArgument(options, 0, "POST");
        final String objectId = options.getString(1);
        final boolean trustEveryone = options.optBoolean(2);
        final boolean chunkedMode = options.optBoolean(3);
        final JSONObject headers = options.optJSONObject(4);
        
        final CordovaResourceApi resourceApi = webView.getResourceApi();

        Log.d(LOG_TAG, "file: " + file);
        Log.d(LOG_TAG, "url: " + url);
        Log.d(LOG_TAG, "httpMethod: " + httpMethod);
        Log.d(LOG_TAG, "objectId: " + objectId);
        Log.d(LOG_TAG, "trustEveryone: " + trustEveryone);
        Log.d(LOG_TAG, "chunkedMode: " + chunkedMode);
        Log.d(LOG_TAG, "headers: " + headers);
        
        final Uri targetUri = resourceApi.remapUri(Uri.parse(url));
        int uriType = CordovaResourceApi.getUriType(targetUri);
        final boolean useHttps = uriType == CordovaResourceApi.URI_TYPE_HTTPS;
        
        Uri tmpSrc = Uri.parse(file);
        final Uri sourceUri = resourceApi.remapUri(tmpSrc.getScheme() != null ? tmpSrc : Uri.fromFile(new File(file)));
        Log.d(LOG_TAG, "sourceUri: " + sourceUri);
        
        final RequestContext context = new RequestContext(url, callbackContext);
        synchronized (activeRequests) {
            activeRequests.put(objectId, context);
        }
        
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                if (context.aborted) {
                    return;
                }
                
                HttpURLConnection conn = null;
                HostnameVerifier oldHostnameVerifier = null;
                SSLSocketFactory oldSocketFactory = null;
                int totalBytes = 0;
                int fixedLength = -1;
                
                try {
                	
                	OpenForReadResult readFileResult = resourceApi.openForRead(sourceUri);
                	byte[] data = readBytes(readFileResult.inputStream);
                	
                	if(encryption.length() > 0) {
                		byte[] key = NaCl.getBinary((String) encryption.get("key"));
                		byte[] IV;
						if(encryption.has("IV")) {
							IV = NaCl.getBinary((String) encryption.get("IV"));
						} else {
							IV = randomBytes(16);
							encryption.put("IV", NaCl.asHex(IV));
						}		
                        
						AlgorithmParameterSpec ivSpec = new IvParameterSpec(IV);
				    	SecretKeySpec newKey = new SecretKeySpec(key, "AES");
				    	Cipher cipher = null;
						cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
						cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
						data = cipher.doFinal(data);
                    }
                	
                	byte[] dataBase64 = Base64.encode(data, Base64.NO_WRAP);
                	String base64 = new String(dataBase64, "US-ASCII");
                			
                	json.put("data", base64);
                	
                	String uploadData = json.toString();
                	
                    // Create return object
                    SimpleDataProgressResult progress = new SimpleDataProgressResult();

                    //------------------ CLIENT REQUEST
                    // Open a HTTP connection to the URL based on protocol
                    conn = resourceApi.createHttpConnection(targetUri);
                    if (useHttps && trustEveryone) {
                        // Setup the HTTPS connection class to trust everyone
                        HttpsURLConnection https = (HttpsURLConnection)conn;
                        oldSocketFactory  = trustAllHosts(https);
                        // Save the current hostnameVerifier
                        oldHostnameVerifier = https.getHostnameVerifier();
                        // Setup the connection not to verify hostnames
                        https.setHostnameVerifier(DO_NOT_VERIFY);
                    }

                    // Allow Inputs
                    conn.setDoInput(true);

                    // Allow Outputs
                    conn.setDoOutput(true);

                    // Don't use a cached copy.
                    conn.setUseCaches(false);

                    // Use a post method.
                    conn.setRequestMethod(httpMethod);
                    conn.setRequestProperty("Content-Type", "application/json");

                    // Set the cookies on the response
                    String cookie = CookieManager.getInstance().getCookie(url);
                    if (cookie != null) {
                        conn.setRequestProperty("Cookie", cookie);
                    }

                    // Handle the other headers
                    if (headers != null) {
                        addHeadersToRequest(conn, headers);
                    }

                    //int stringLength = beforeDataBytes.length + tailParamsBytes.length;
                    fixedLength = uploadData.length();
                    progress.setTotal(fixedLength);
                    
                    Log.d(LOG_TAG, "Content Length: " + fixedLength);
                    
                    if (chunkedMode) {
                        conn.setChunkedStreamingMode(MAX_BUFFER_SIZE);
                        // Although setChunkedStreamingMode sets this header, setting it explicitly here works
                        // around an OutOfMemoryException when using https.
                        conn.setRequestProperty("Transfer-Encoding", "chunked");
                    } else {
                        conn.setFixedLengthStreamingMode(fixedLength);
                    }

                    conn.connect();
                    
                    OutputStream sendStream = null;
                    InputStream readResult = new ByteArrayInputStream(uploadData.getBytes());
                    try {
                        sendStream = conn.getOutputStream();
                        synchronized (context) {
                            if (context.aborted) {
                                return;
                            }
                            context.connection = conn;
                        }
                        
                        // create a buffer of maximum size
                        int bytesAvailable = readResult.available();
                        int bufferSize = Math.min(bytesAvailable, MAX_BUFFER_SIZE);
                        byte[] buffer = new byte[bufferSize];
    
                        // read file and write it into form...
                        int bytesRead = readResult.read(buffer, 0, bufferSize);
    
                        long prevBytesRead = 0;
                        while (bytesRead > 0) {
                            sendStream.write(buffer, 0, bytesRead);
                            totalBytes += bytesRead;
                            if (totalBytes > prevBytesRead + 102400) {
                                prevBytesRead = totalBytes;
                                Log.d(LOG_TAG, "Uploaded " + totalBytes + " of " + fixedLength + " bytes");
                            }
                            bytesAvailable = readResult.available();
                            bufferSize = Math.min(bytesAvailable, MAX_BUFFER_SIZE);
                            bytesRead = readResult.read(buffer, 0, bufferSize);

                            // Send a progress event.
                            progress.setLoaded(totalBytes);
                            PluginResult progressResult = new PluginResult(PluginResult.Status.OK, progress.toJSONObject());
                            progressResult.setKeepCallback(true);
                            context.sendPluginResult(progressResult);
                        }
    
                       sendStream.flush();
                    } finally {
                    	safeClose(readResult);
                        safeClose(sendStream);
                    }
                    synchronized (context) {
                        context.connection = null;
                    }
                    Log.d(LOG_TAG, "Sent " + totalBytes + " of " + fixedLength);

                    //------------------ read the SERVER RESPONSE
                    String responseString;
                    int responseCode = conn.getResponseCode();
                    Log.d(LOG_TAG, "response code: " + responseCode);
                    Log.d(LOG_TAG, "response headers: " + conn.getHeaderFields());
                    TrackingInputStream inStream = null;
                    try {
                        inStream = getInputStream(conn);
                        synchronized (context) {
                            if (context.aborted) {
                                return;
                            }
                            context.connection = conn;
                        }
                        
                        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(1024, conn.getContentLength()));
                        byte[] buffer = new byte[1024];
                        int bytesRead = 0;
                        // write bytes to file
                        while ((bytesRead = inStream.read(buffer)) > 0) {
                            out.write(buffer, 0, bytesRead);
                        }
                        responseString = out.toString("UTF-8");
                    } finally {
                        synchronized (context) {
                            context.connection = null;
                        }
                        safeClose(inStream);
                    }
                    
                    Log.d(LOG_TAG, "got response from server");
                    Log.d(LOG_TAG, responseString.substring(0, Math.min(256, responseString.length())));
                    
                    JSONObject result = new JSONObject(
                            "{bytesSent:" + totalBytes +
                            ",responseCode:" + responseCode +
                            ",response:" + JSONObject.quote(responseString) +
                            ",objectId:" + JSONObject.quote(objectId) + "}");
                    
                    if(encryption.length() > 0) {
                    	result.putOpt("encryption", encryption);
                    }
                    
                    context.sendPluginResult(new PluginResult(PluginResult.Status.OK, result));
                } catch (IOException e) {
                    JSONObject error = createSimpleDataTransferError(CONNECTION_ERR, url, conn, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    Log.e(LOG_TAG, "Failed after uploading " + totalBytes + " of " + fixedLength + " bytes.");
                    context.sendPluginResult(new PluginResult(PluginResult.Status.IO_EXCEPTION, error));
                } catch (JSONException e) {
                    Log.e(LOG_TAG, e.getMessage(), e);
                    context.sendPluginResult(new PluginResult(PluginResult.Status.JSON_EXCEPTION));
                } catch (Throwable t) {
                    // Shouldn't happen, but will
                    JSONObject error = createSimpleDataTransferError(CONNECTION_ERR, url, conn, t);
                    Log.e(LOG_TAG, error.toString(), t);
                    context.sendPluginResult(new PluginResult(PluginResult.Status.IO_EXCEPTION, error));
                } finally {
                    synchronized (activeRequests) {
                        activeRequests.remove(objectId);
                    }

                    if (conn != null) {
                        // Revert back to the proper verifier and socket factories
                        if (trustEveryone && useHttps) {
                            HttpsURLConnection https = (HttpsURLConnection) conn;
                            https.setHostnameVerifier(oldHostnameVerifier);
                            https.setSSLSocketFactory(oldSocketFactory);
                        }
                    }
                }                
            }
        });
    }
    
    private static void safeClose(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
            }
        }
    }

    private static TrackingInputStream getInputStream(URLConnection conn) throws IOException {
        String encoding = conn.getContentEncoding();
        if (encoding != null && encoding.equalsIgnoreCase("gzip")) {
          return new TrackingGZIPInputStream(new ExposedGZIPInputStream(conn.getInputStream()));
        }
        return new SimpleTrackingInputStream(conn.getInputStream());
    }

    // always verify the host - don't check for certificate
    private static final HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
    // Create a trust manager that does not validate certificate chains
    private static final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }
        
        public void checkClientTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
        }
        
        public void checkServerTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
        }
    } };

    /**
     * This function will install a trust manager that will blindly trust all SSL
     * certificates.  The reason this code is being added is to enable developers
     * to do development using self signed SSL certificates on their web server.
     *
     * The standard HttpsURLConnection class will throw an exception on self
     * signed certificates if this code is not run.
     */
    private static SSLSocketFactory trustAllHosts(HttpsURLConnection connection) {
        // Install the all-trusting trust manager
        SSLSocketFactory oldFactory = connection.getSSLSocketFactory();
        try {
            // Install our all trusting manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory newFactory = sc.getSocketFactory();
            connection.setSSLSocketFactory(newFactory);
        } catch (Exception e) {
            Log.e(LOG_TAG, e.getMessage(), e);
        }
        return oldFactory;
    }

    private static JSONObject createSimpleDataTransferError(int errorCode, String url, URLConnection connection, Throwable throwable) {

        int httpStatus = 0;
        StringBuilder bodyBuilder = new StringBuilder();
        String body = null;
        if (connection != null) {
            try {
                if (connection instanceof HttpURLConnection) {
                    httpStatus = ((HttpURLConnection)connection).getResponseCode();
                    InputStream err = ((HttpURLConnection) connection).getErrorStream();
                    if(err != null)
                    {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(err, "UTF-8"));
                        try {
                            String line = reader.readLine();
                            while(line != null) {
                                bodyBuilder.append(line);
                                line = reader.readLine();
                                if(line != null) {
                                    bodyBuilder.append('\n');
                                }
                            }
                            body = bodyBuilder.toString();
                        } finally {
                            reader.close();
                        }
                    }
                }
            // IOException can leave connection object in a bad state, so catch all exceptions.
            } catch (Throwable e) {
                Log.w(LOG_TAG, "Error getting HTTP status code from connection.", e);
            }
        }

        return createSimpleDataTransferError(errorCode, url, body, httpStatus, throwable);
    }

        /**
        * Create an error object based on the passed in errorCode
        * @param errorCode      the error
        * @return JSONObject containing the error
        */
    private static JSONObject createSimpleDataTransferError(int errorCode, String url, String body, Integer httpStatus, Throwable throwable) {
        JSONObject error = null;
        try {
            error = new JSONObject();
            error.put("code", errorCode);
            error.put("url", url);
            if(body != null)
            {
                error.put("body", body);
            }   
            if (httpStatus != null) {
                error.put("http_status", httpStatus);
            }
            if (throwable != null) {
                String msg = throwable.getMessage();
                if (msg == null || "".equals(msg)) {
                    msg = throwable.toString();
                }
                error.put("exception", msg);
            }
        } catch (JSONException e) {
            Log.e(LOG_TAG, e.getMessage(), e);
        }
        return error;
    }

    /**
     * Convenience method to read a parameter from the list of JSON args.
     * @param args                      the args passed to the Plugin
     * @param position          the position to retrieve the arg from
     * @param defaultString the default to be used if the arg does not exist
     * @return String with the retrieved value
     */
    private static String getArgument(JSONArray args, int position, String defaultString) {
        String arg = defaultString;
        if (args.length() > position) {
            arg = args.optString(position);
            if (arg == null || "null".equals(arg)) {
                arg = defaultString;
            }
        }
        return arg;
    }

    private void downloadFileAsJson(final JSONArray args, CallbackContext callbackContext) throws JSONException {
    	final String file = args.getString(0);
    	final String url = args.getString(1);
        
        final JSONArray options = args.optJSONArray(2);
        final JSONObject encryption = args.optJSONObject(3);
    	
    	Log.d(LOG_TAG, "download from " + url);

        final CordovaResourceApi resourceApi = webView.getResourceApi();

        final boolean trustEveryone = options.optBoolean(0);
        final String objectId = options.getString(1);
        final JSONObject headers = options.optJSONObject(2);
        
        final Uri sourceUri = resourceApi.remapUri(Uri.parse(url));
        
        int uriType = CordovaResourceApi.getUriType(sourceUri);
        final boolean useHttps = uriType == CordovaResourceApi.URI_TYPE_HTTPS;
        
        Uri tmpTarget = Uri.parse(file);
        final Uri targetUri = resourceApi.remapUri(
            tmpTarget.getScheme() != null ? tmpTarget : Uri.fromFile(new File(file)));

        
        final RequestContext context = new RequestContext(url, callbackContext);
        synchronized (activeRequests) {
            activeRequests.put(objectId, context);
        }
        
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                if (context.aborted) {
                    return;
                }
                HttpURLConnection connection = null;
                HostnameVerifier oldHostnameVerifier = null;
                SSLSocketFactory oldSocketFactory = null;
                PluginResult result = null;
                TrackingInputStream inputStream = null;

                OutputStream outputStream = new ByteArrayOutputStream();
                try {
                     
                    Log.d(LOG_TAG, "Download file:" + sourceUri);

                    SimpleDataProgressResult progress = new SimpleDataProgressResult();

                    // connect to server
                    // Open a HTTP connection to the URL based on protocol
                    connection = resourceApi.createHttpConnection(sourceUri);
                    if (useHttps && trustEveryone) {
                        // Setup the HTTPS connection class to trust everyone
                        HttpsURLConnection https = (HttpsURLConnection)connection;
                        oldSocketFactory = trustAllHosts(https);
                        // Save the current hostnameVerifier
                        oldHostnameVerifier = https.getHostnameVerifier();
                        // Setup the connection not to verify hostnames
                        https.setHostnameVerifier(DO_NOT_VERIFY);
                    }
    
                    connection.setRequestMethod("GET");
    
                    // TODO: Make OkHttp use this CookieManager by default.
                    String cookie = CookieManager.getInstance().getCookie(sourceUri.toString());
                    if(cookie != null)
                    {
                        connection.setRequestProperty("cookie", cookie);
                    }
                    
                    // This must be explicitly set for gzip progress tracking to work.
                    connection.setRequestProperty("Accept-Encoding", "gzip");

                    // Handle the other headers
                    if (headers != null) {
                        addHeadersToRequest(connection, headers);
                    }
    
                    connection.connect();

                    if (connection.getContentEncoding() == null || connection.getContentEncoding().equalsIgnoreCase("gzip")) {
                        // Only trust content-length header if we understand
                        // the encoding -- identity or gzip
                        if (connection.getContentLength() != -1) {
                            progress.setTotal(connection.getContentLength());
                        }
                    }
                    inputStream = getInputStream(connection);
                    
                    try {
                        synchronized (context) {
                            if (context.aborted) {
                                return;
                            }
                            context.connection = connection;
                        }
                        
                        // write bytes to file
                        byte[] buffer = new byte[MAX_BUFFER_SIZE];
                        int bytesRead = 0;
                        while ((bytesRead = inputStream.read(buffer)) > 0) {
                            outputStream.write(buffer, 0, bytesRead);
                            // Send a progress event.
                            progress.setLoaded(inputStream.getTotalRawBytesRead());
                            PluginResult progressResult = new PluginResult(PluginResult.Status.OK, progress.toJSONObject());
                            progressResult.setKeepCallback(true);
                            context.sendPluginResult(progressResult);
                        }
                    } finally {
                        synchronized (context) {
                            context.connection = null;
                        }
                        safeClose(inputStream);
                        safeClose(outputStream);
                    }
    
                    Log.d(LOG_TAG, "Saved file: " + url);
    
                    JSONObject jsonData = new JSONObject(outputStream.toString());
                    
                    if(jsonData.has("data")) {
                    	byte[] fileData = Base64.decode(jsonData.getString("data"), Base64.NO_WRAP);
                        if(encryption.length() > 0) {
                        	
                    		byte[] key = NaCl.getBinary((String) encryption.get("key"));
    						byte[] IV = NaCl.getBinary((String) encryption.get("IV"));
    						
    						AlgorithmParameterSpec ivSpec = new IvParameterSpec(IV);
    						SecretKeySpec newKey = new SecretKeySpec(key, "AES");
    						Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    						cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
    						fileData = cipher.doFinal(fileData);
                        }
                        
                        // calc md5 
                        byte[] base64FileData = Base64.encode(fileData, Base64.NO_WRAP);
                        MessageDigest md = MessageDigest.getInstance("MD5");
						md.update(base64FileData);
						byte[] digest = md.digest();
						StringBuffer sb = new StringBuffer();
						for (byte b : digest) {
							sb.append(String.format("%02x", b & 0xff));
						}
                        
						String md5 = sb.toString();
						jsonData.put("hash", md5);
						
                        jsonData.remove("data");
                        
                        InputStream readResult = new ByteArrayInputStream(fileData);
                        OutputStream fileOutputStream = resourceApi.openOutputStream(targetUri);
                        
                        byte[] buffer = new byte[MAX_BUFFER_SIZE];
                        int bytesRead = 0;
                        
                        // write bytes to file
                        while ((bytesRead = readResult.read(buffer)) > 0) {
                        	fileOutputStream.write(buffer, 0, bytesRead);
                        }
                        
                        // set the file size
                        jsonData.put("size", fileData.length);
                        
                        safeClose(readResult);
                        safeClose(fileOutputStream);
                        
                    } else {
                    	//TODO error
                    }
                    
                    FileUtils filePlugin = (FileUtils)webView.pluginManager.getPlugin("File");
                    File file = resourceApi.mapUriToFile(targetUri);
                    JSONObject fileEntry = filePlugin.getEntryForFile(file);
                    
                    JSONObject data = new JSONObject(
                            "{bytesReceived:" + outputStream.toString().length() +
                            ",responseCode:" + connection.getResponseCode() +
                            ",objectId:" + JSONObject.quote(objectId) + "}");
                    
                    data.putOpt("file", fileEntry);
                    data.putOpt("json", jsonData);
                    
                    result = new PluginResult(PluginResult.Status.OK, data);
                    
                } catch (IOException e) {
                    JSONObject error = createSimpleDataTransferError(CONNECTION_ERR, url, connection, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                } catch (JSONException e) {
                    Log.e(LOG_TAG, e.getMessage(), e);
                    result = new PluginResult(PluginResult.Status.JSON_EXCEPTION);
                } catch (Throwable e) {
                    JSONObject error = createSimpleDataTransferError(CONNECTION_ERR, url, connection, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                } finally {
                    safeClose(outputStream);
                    synchronized (activeRequests) {
                        activeRequests.remove(objectId);
                    }

                    if (connection != null) {
                        // Revert back to the proper verifier and socket factories
                        if (trustEveryone && useHttps) {
                            HttpsURLConnection https = (HttpsURLConnection) connection;
                            https.setHostnameVerifier(oldHostnameVerifier);
                            https.setSSLSocketFactory(oldSocketFactory);
                        }
                    }

                    if (result == null) {
                        result = new PluginResult(PluginResult.Status.ERROR, createSimpleDataTransferError(CONNECTION_ERR, url, connection, null));
                    }
                    
                    context.sendPluginResult(result);
                }
            }
        });
    }
    
    /**
     * Abort an ongoing upload or download.
     */
    private void abort(String objectId) {
        final RequestContext context;
        synchronized (activeRequests) {
            context = activeRequests.remove(objectId);
        }
        if (context != null) {
            // Closing the streams can block, so execute on a background thread.
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    synchronized (context) {
                        File file = context.targetFile;
                        if (file != null) {
                            file.delete();
                        }
                        // Trigger the abort callback immediately to minimize latency between it and abort() being called.
                        JSONObject error = createSimpleDataTransferError(ABORTED_ERR, context.source, null, -1, null);
                        context.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, error));
                        context.aborted = true;
                        if (context.connection != null) {
                            context.connection.disconnect();
                        }
                    }
                }
            });
        }
    }
    
    public static byte[] readBytes(InputStream inputStream) throws IOException {
	  // this dynamically extends to take the bytes you read
	  ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();

	  // this is storage overwritten on each iteration with bytes
	  int bufferSize = 1024;
	  byte[] buffer = new byte[bufferSize];

	  // we need to know how may bytes were read to write them to the byteBuffer
	  int len = 0;
	  while ((len = inputStream.read(buffer)) != -1) {
	    byteBuffer.write(buffer, 0, len);
	  }

	  // and then we can return your byte array.
	  return byteBuffer.toByteArray();
	}
    
    private static byte[] randomBytes(int n) {
        byte[] buffer = new byte[n];
        try {
        	SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        	secureRandom.nextBytes(buffer);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        return buffer;
    }
}
