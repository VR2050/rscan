package com.ding.rtc.http;

import android.os.Build;
import android.text.TextUtils;
import android.util.Log;
import com.ding.rtc.task.SimpleTask;
import com.ding.rtc.task.TaskExecutor;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.ProxyInfo;

/* JADX INFO: loaded from: classes.dex */
public class HttpStack {
    private static final String ALIYUN_DNS_HOST = "203.107.1.1";
    private static final String TAG = "HttpStack";

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException e) {
        }
    }

    static boolean isIP(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static HttpURLConnection createConnection(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());
        return connection;
    }

    private static HttpURLConnection openConnection(URL url, String method, Map<String, String> headers, byte[] body, int timeoutMs) throws IOException {
        HttpURLConnection connection = createConnection(url);
        connection.setRequestMethod(method);
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setUseCaches(false);
        connection.setDoInput(true);
        configHttps(connection, null);
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        if (body != null && body.length > 0) {
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            if (headers != null && "gzip".equals(headers.get(HttpHeaders.CONTENT_ENCODING))) {
                os = new GZIPOutputStream(new BufferedOutputStream(os));
            }
            os.write(body);
            os.flush();
            closeQuietly(os);
        }
        return connection;
    }

    private static HttpURLConnection openConnection(URL url, String method, Map<String, String> headers, int timeoutMs) throws IOException {
        HttpURLConnection connection = createConnection(url);
        connection.setRequestMethod(method);
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setUseCaches(false);
        connection.setDoInput(true);
        configHttps(connection, null);
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        return connection;
    }

    public static HttpStackResponse doPostSNI(String path, Map<String, String> headers, byte[] body, int timeoutMs, String ip, String host) {
        return doHttpMethod(path, headers, body, timeoutMs, ip, host, "POST");
    }

    public static HttpStackResponse doGetSNI(String path, Map<String, String> headers, byte[] body, int timeoutMs, String ip, String host) {
        return doHttpMethod(path, headers, body, timeoutMs, ip, host, "GET");
    }

    public static boolean doAsyncGetUpload(final String url, final Map<String, String> headers, final String filePath, final int timeoutMs, final HttpAsyncResponse response) {
        if (TextUtils.isEmpty(url) || response == null) {
            return false;
        }
        TaskExecutor.execute(new SimpleTask() { // from class: com.ding.rtc.http.HttpStack.1
            @Override // java.lang.Runnable
            public void run() throws Throwable {
                HttpStackResponse httpStackResponse = HttpStack.doGet(url, headers, HttpStack.getFileBytes(filePath), timeoutMs, filePath);
                response.onHttpResult(httpStackResponse);
            }
        });
        return true;
    }

    public static boolean doAsyncGet(final String url, final Map<String, String> headers, final byte[] body, final int timeoutMs, final String filePath, final HttpAsyncResponse response) {
        if (TextUtils.isEmpty(url) || response == null) {
            return false;
        }
        TaskExecutor.execute(new SimpleTask() { // from class: com.ding.rtc.http.HttpStack.2
            @Override // java.lang.Runnable
            public void run() throws Throwable {
                HttpStackResponse httpStackResponse = HttpStack.doGet(url, headers, body, timeoutMs, filePath);
                response.onHttpResult(httpStackResponse);
            }
        });
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00e3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.ding.rtc.http.HttpStackResponse doGet(java.lang.String r20, java.util.Map<java.lang.String, java.lang.String> r21, byte[] r22, int r23, java.lang.String r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 231
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ding.rtc.http.HttpStack.doGet(java.lang.String, java.util.Map, byte[], int, java.lang.String):com.ding.rtc.http.HttpStackResponse");
    }

    public static boolean doAsyncPostUpload(final String url, final Map<String, String> headers, final String filePath, final int timeoutMs, final HttpAsyncResponse response) {
        if (TextUtils.isEmpty(url) || response == null) {
            return false;
        }
        TaskExecutor.execute(new SimpleTask() { // from class: com.ding.rtc.http.HttpStack.3
            @Override // java.lang.Runnable
            public void run() throws Throwable {
                HttpStackResponse httpStackResponse = HttpStack.doPost(url, headers, HttpStack.getFileBytes(filePath), timeoutMs, filePath);
                response.onHttpResult(httpStackResponse);
            }
        });
        return true;
    }

    public static boolean doAsyncPost(final String url, final Map<String, String> headers, final byte[] body, final int timeoutMs, final String filePath, final HttpAsyncResponse response) {
        if (TextUtils.isEmpty(url) || response == null) {
            return false;
        }
        TaskExecutor.execute(new SimpleTask() { // from class: com.ding.rtc.http.HttpStack.4
            @Override // java.lang.Runnable
            public void run() throws Throwable {
                HttpStackResponse httpStackResponse = new HttpStackResponse();
                String newUrl = url;
                try {
                    URL address = new URL(newUrl);
                    String host = address.getHost();
                    boolean isIPHost = HttpStack.isIP(host);
                    boolean isHttps = url.startsWith(ProxyInfo.TYPE_HTTPS);
                    if (isIPHost && isHttps && headers.containsKey("Host")) {
                        String header_host = (String) headers.get("Host");
                        response.onHttpResult(HttpStack.doPostSNI(newUrl.replaceFirst(host, header_host), headers, body, timeoutMs, host, header_host));
                    } else {
                        response.onHttpResult(HttpStack.doPost(url, headers, body, timeoutMs, filePath));
                    }
                } catch (MalformedURLException e) {
                    httpStackResponse.code = -1;
                    httpStackResponse.result = "url wrong, malformed exception".getBytes();
                    response.onHttpResult(httpStackResponse);
                }
            }
        });
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x0117  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.ding.rtc.http.HttpStackResponse doPost(java.lang.String r20, java.util.Map<java.lang.String, java.lang.String> r21, byte[] r22, int r23, java.lang.String r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 283
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ding.rtc.http.HttpStack.doPost(java.lang.String, java.util.Map, byte[], int, java.lang.String):com.ding.rtc.http.HttpStackResponse");
    }

    public static HttpStackResponse multipartPost(String url, String BOUNDARY, String LINE_FEED, Map<String, String> headers, MultipartWriter writer) {
        HttpStackResponse response = null;
        OutputStream outputStream = null;
        PrintWriter printWriter = null;
        HttpURLConnection conn = null;
        try {
            try {
                URL requestedUrl = new URL(url);
                conn = openConnection(requestedUrl, "POST", headers, 3000);
                conn.setDoOutput(true);
                outputStream = conn.getOutputStream();
                printWriter = (headers == null || !"gzip".equals(headers.get(HttpHeaders.CONTENT_ENCODING))) ? new PrintWriter(outputStream) : new PrintWriter(new GZIPOutputStream(outputStream));
                writer.addPart(printWriter, outputStream);
                printWriter.append((CharSequence) LINE_FEED);
                printWriter.append("--").append((CharSequence) BOUNDARY).append("--").append((CharSequence) LINE_FEED);
                printWriter.flush();
                int responseCode = conn.getResponseCode();
                long lastModified = conn.getLastModified();
                response = new HttpStackResponse();
                response.code = responseCode;
                response.result = readFully(conn.getInputStream());
                response.lastModified = lastModified;
                printWriter.close();
                if (outputStream != null) {
                    try {
                        outputStream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } finally {
            }
        } catch (MalformedURLException e2) {
            e2.printStackTrace();
            if (printWriter != null) {
                printWriter.close();
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e3) {
                    e3.printStackTrace();
                }
            }
            if (conn != null) {
            }
        } catch (IOException e4) {
            e4.printStackTrace();
            if (printWriter != null) {
                printWriter.close();
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e5) {
                    e5.printStackTrace();
                }
            }
            if (conn != null) {
            }
        }
        if (conn != null) {
            conn.disconnect();
        }
        return response;
    }

    private static byte[] readFully(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return new byte[0];
        }
        BufferedInputStream bufferedInputStream = null;
        try {
            bufferedInputStream = new BufferedInputStream(inputStream);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (true) {
                int available = bufferedInputStream.read(buffer);
                if (available >= 0) {
                    byteArrayOutputStream.write(buffer, 0, available);
                } else {
                    return byteArrayOutputStream.toByteArray();
                }
            }
        } finally {
            closeQuietly(bufferedInputStream);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] getFileBytes(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            return null;
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while (true) {
                int available = fis.read(buffer);
                if (available < 0) {
                    byte[] result = byteArrayOutputStream.toByteArray();
                    return result;
                }
                byteArrayOutputStream.write(buffer, 0, available);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            closeQuietly(fis);
        }
    }

    private static void saveFile(InputStream inputStream, String filePath) {
        if (inputStream == null || TextUtils.isEmpty(filePath)) {
            return;
        }
        FileOutputStream fos = null;
        try {
            try {
                FileUtil.createFilePath(null, filePath);
                File file = new File(filePath);
                fos = new FileOutputStream(file);
                byte[] buffer = new byte[1024];
                while (true) {
                    int available = inputStream.read(buffer);
                    if (available < 0) {
                        break;
                    } else {
                        fos.write(buffer, 0, available);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } finally {
            closeQuietly(fos);
            closeQuietly(inputStream);
        }
    }

    private static void configHttps(HttpURLConnection urlConnection, final String verifyHost) {
        if (Build.VERSION.SDK_INT < 22) {
            configHttpsOnPreLollipop(urlConnection, verifyHost);
            return;
        }
        if (!(urlConnection instanceof HttpsURLConnection)) {
            return;
        }
        HttpsURLConnection conn = (HttpsURLConnection) urlConnection;
        try {
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(null, null, null);
            conn.setSSLSocketFactory(sslcontext.getSocketFactory());
            HostnameVerifier hostnameVerifier = new HostnameVerifier() { // from class: com.ding.rtc.http.HttpStack.5
                @Override // javax.net.ssl.HostnameVerifier
                public boolean verify(String hostname, SSLSession session) {
                    HostnameVerifier defaultHostVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                    if (defaultHostVerifier.verify(HttpStack.ALIYUN_DNS_HOST, session)) {
                        return true;
                    }
                    if (TextUtils.isEmpty(verifyHost)) {
                        return defaultHostVerifier.verify(hostname, session);
                    }
                    return verifyHost.equals(hostname) || defaultHostVerifier.verify(verifyHost, session);
                }
            };
            conn.setHostnameVerifier(hostnameVerifier);
        } catch (Exception e) {
            e.printStackTrace();
            Logging.e(TAG, "configHttps error:" + Log.getStackTraceString(e));
        }
    }

    private static void configHttpsOnPreLollipop(HttpURLConnection urlConnection, final String verifyHost) {
        if (!(urlConnection instanceof HttpsURLConnection) || Build.VERSION.SDK_INT >= 22) {
            return;
        }
        HttpsURLConnection conn = (HttpsURLConnection) urlConnection;
        try {
            conn.setSSLSocketFactory(new PreLollipopTLSSocketFactory());
            HostnameVerifier hostnameVerifier = new HostnameVerifier() { // from class: com.ding.rtc.http.HttpStack.6
                @Override // javax.net.ssl.HostnameVerifier
                public boolean verify(String hostname, SSLSession session) {
                    HostnameVerifier defaultHostVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                    if (defaultHostVerifier.verify(HttpStack.ALIYUN_DNS_HOST, session)) {
                        return true;
                    }
                    if (TextUtils.isEmpty(verifyHost)) {
                        return defaultHostVerifier.verify(hostname, session);
                    }
                    return verifyHost.equals(hostname) || defaultHostVerifier.verify(verifyHost, session);
                }
            };
            conn.setHostnameVerifier(hostnameVerifier);
        } catch (Exception exc) {
            Logging.e(TAG, "Error while setting TLS 1.2" + Log.getStackTraceString(exc));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0307  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x01c2  */
    /* JADX WARN: Type inference failed for: r2v0, types: [javax.net.ssl.HttpsURLConnection] */
    /* JADX WARN: Type inference failed for: r2v1, types: [javax.net.ssl.HttpsURLConnection] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v2, types: [javax.net.ssl.HttpsURLConnection] */
    /* JADX WARN: Type inference failed for: r2v24 */
    /* JADX WARN: Type inference failed for: r2v25 */
    /* JADX WARN: Type inference failed for: r2v26 */
    /* JADX WARN: Type inference failed for: r2v27 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v37 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r9v12 */
    /* JADX WARN: Type inference failed for: r9v3 */
    /* JADX WARN: Type inference failed for: r9v4, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Type inference failed for: r9v6 */
    /* JADX WARN: Type inference failed for: r9v8 */
    /* JADX WARN: Type inference failed for: r9v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static com.ding.rtc.http.HttpStackResponse doHttpMethod(java.lang.String r25, java.util.Map<java.lang.String, java.lang.String> r26, byte[] r27, int r28, java.lang.String r29, java.lang.String r30, java.lang.String r31) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 829
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ding.rtc.http.HttpStack.doHttpMethod(java.lang.String, java.util.Map, byte[], int, java.lang.String, java.lang.String, java.lang.String):com.ding.rtc.http.HttpStackResponse");
    }

    private static boolean needRedirect(int code) {
        return code >= 300 && code < 400;
    }
}
