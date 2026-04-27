package okhttp3.logging;

import java.io.EOFException;
import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;
import okhttp3.Connection;
import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.internal.http.HttpHeaders;
import okhttp3.internal.platform.Platform;
import okio.Buffer;
import okio.BufferedSource;
import okio.GzipSource;

/* JADX INFO: loaded from: classes3.dex */
public final class HttpLoggingInterceptor implements Interceptor {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private volatile Level level;
    private final Logger logger;

    public enum Level {
        NONE,
        BASIC,
        HEADERS,
        BODY
    }

    public interface Logger {
        public static final Logger DEFAULT = new Logger() { // from class: okhttp3.logging.HttpLoggingInterceptor.Logger.1
            @Override // okhttp3.logging.HttpLoggingInterceptor.Logger
            public void log(String message) {
                Platform.get().log(4, message, null);
            }
        };

        void log(String str);
    }

    public HttpLoggingInterceptor() {
        this(Logger.DEFAULT);
    }

    public HttpLoggingInterceptor(Logger logger) {
        this.level = Level.NONE;
        this.logger = logger;
    }

    public HttpLoggingInterceptor setLevel(Level level) {
        if (level == null) {
            throw new NullPointerException("level == null. Use Level.NONE instead.");
        }
        this.level = level;
        return this;
    }

    public Level getLevel() {
        return this.level;
    }

    @Override // okhttp3.Interceptor
    public Response intercept(Interceptor.Chain chain) throws Exception {
        String str;
        String requestStartMessage;
        boolean logBody;
        String str2;
        String str3;
        long contentLength;
        char c;
        String string;
        String str4;
        String str5;
        String requestStartMessage2;
        int count;
        Level level = this.level;
        Request request = chain.request();
        if (level == Level.NONE) {
            return chain.proceed(request);
        }
        boolean logBody2 = level == Level.BODY;
        boolean logHeaders = logBody2 || level == Level.HEADERS;
        RequestBody requestBody = request.body();
        boolean hasRequestBody = requestBody != null;
        Connection connection = chain.connection();
        StringBuilder sb = new StringBuilder();
        sb.append("--> ");
        sb.append(request.method());
        sb.append(' ');
        sb.append(request.url());
        sb.append(connection != null ? " " + connection.protocol() : "");
        String requestStartMessage3 = sb.toString();
        String str6 = "-byte body)";
        if (logHeaders || !hasRequestBody) {
            str = "";
            requestStartMessage = requestStartMessage3;
        } else {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(requestStartMessage3);
            sb2.append(" (");
            str = "";
            sb2.append(requestBody.contentLength());
            sb2.append("-byte body)");
            requestStartMessage = sb2.toString();
        }
        this.logger.log(requestStartMessage);
        if (logHeaders) {
            if (!hasRequestBody) {
                str4 = "-byte body)";
                str5 = " (";
            } else {
                if (requestBody.contentType() != null) {
                    this.logger.log("Content-Type: " + requestBody.contentType());
                }
                if (requestBody.contentLength() == -1) {
                    str4 = "-byte body)";
                    str5 = " (";
                } else {
                    Logger logger = this.logger;
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Content-Length: ");
                    str4 = "-byte body)";
                    str5 = " (";
                    sb3.append(requestBody.contentLength());
                    logger.log(sb3.toString());
                }
            }
            Headers headers = request.headers();
            int i = 0;
            int count2 = headers.size();
            while (i < count2) {
                String name = headers.name(i);
                Connection connection2 = connection;
                if ("Content-Type".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) {
                    requestStartMessage2 = requestStartMessage;
                    count = count2;
                } else {
                    Logger logger2 = this.logger;
                    requestStartMessage2 = requestStartMessage;
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append(name);
                    sb4.append(": ");
                    count = count2;
                    sb4.append(headers.value(i));
                    logger2.log(sb4.toString());
                }
                i++;
                connection = connection2;
                requestStartMessage = requestStartMessage2;
                count2 = count;
            }
            if (logBody2 && hasRequestBody) {
                if (bodyHasUnknownEncoding(request.headers())) {
                    this.logger.log("--> END " + request.method() + " (encoded body omitted)");
                    str6 = str4;
                    str2 = str;
                    logBody = logBody2;
                    str3 = str5;
                } else {
                    Buffer buffer = new Buffer();
                    requestBody.writeTo(buffer);
                    Charset charset = UTF8;
                    MediaType contentType = requestBody.contentType();
                    if (contentType != null) {
                        charset = contentType.charset(UTF8);
                    }
                    str2 = str;
                    this.logger.log(str2);
                    if (!isPlaintext(buffer)) {
                        str6 = str4;
                        str3 = str5;
                        Logger logger3 = this.logger;
                        StringBuilder sb5 = new StringBuilder();
                        sb5.append("--> END ");
                        sb5.append(request.method());
                        sb5.append(" (binary ");
                        logBody = logBody2;
                        sb5.append(requestBody.contentLength());
                        sb5.append("-byte body omitted)");
                        logger3.log(sb5.toString());
                    } else {
                        this.logger.log(buffer.readString(charset));
                        Logger logger4 = this.logger;
                        StringBuilder sb6 = new StringBuilder();
                        sb6.append("--> END ");
                        sb6.append(request.method());
                        String str7 = str5;
                        sb6.append(str7);
                        sb6.append(requestBody.contentLength());
                        str6 = str4;
                        sb6.append(str6);
                        logger4.log(sb6.toString());
                        str3 = str7;
                        logBody = logBody2;
                    }
                }
            } else {
                str6 = str4;
                str2 = str;
                logBody = logBody2;
                str3 = str5;
                this.logger.log("--> END " + request.method());
            }
        } else {
            logBody = logBody2;
            str2 = str;
            str3 = " (";
        }
        long startNs = System.nanoTime();
        try {
            Response response = chain.proceed(request);
            String bodySize = str2;
            long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
            ResponseBody responseBody = response.body();
            long contentLength2 = responseBody.contentLength();
            String bodySize2 = contentLength2 != -1 ? contentLength2 + "-byte" : "unknown-length";
            Logger logger5 = this.logger;
            StringBuilder sb7 = new StringBuilder();
            String str8 = str6;
            sb7.append("<-- ");
            sb7.append(response.code());
            if (response.message().isEmpty()) {
                contentLength = contentLength2;
                string = bodySize;
                c = ' ';
            } else {
                StringBuilder sb8 = new StringBuilder();
                contentLength = contentLength2;
                c = ' ';
                sb8.append(' ');
                sb8.append(response.message());
                string = sb8.toString();
            }
            sb7.append(string);
            sb7.append(c);
            sb7.append(response.request().url());
            sb7.append(str3);
            sb7.append(tookMs);
            sb7.append("ms");
            sb7.append(logHeaders ? bodySize : ", " + bodySize2 + " body");
            sb7.append(')');
            logger5.log(sb7.toString());
            if (logHeaders) {
                Headers headers2 = response.headers();
                int count3 = headers2.size();
                for (int i2 = 0; i2 < count3; i2++) {
                    this.logger.log(headers2.name(i2) + ": " + headers2.value(i2));
                }
                if (logBody && HttpHeaders.hasBody(response)) {
                    if (bodyHasUnknownEncoding(response.headers())) {
                        this.logger.log("<-- END HTTP (encoded body omitted)");
                    } else {
                        BufferedSource source = responseBody.source();
                        source.request(Long.MAX_VALUE);
                        Buffer buffer2 = source.buffer();
                        Long gzippedLength = null;
                        if ("gzip".equalsIgnoreCase(headers2.get(com.ding.rtc.http.HttpHeaders.CONTENT_ENCODING))) {
                            gzippedLength = Long.valueOf(buffer2.size());
                            GzipSource gzippedResponseBody = null;
                            try {
                                gzippedResponseBody = new GzipSource(buffer2.clone());
                                buffer2 = new Buffer();
                                buffer2.writeAll(gzippedResponseBody);
                                gzippedResponseBody.close();
                            } catch (Throwable th) {
                                if (gzippedResponseBody != null) {
                                    gzippedResponseBody.close();
                                }
                                throw th;
                            }
                        }
                        Charset charset2 = UTF8;
                        MediaType contentType2 = responseBody.contentType();
                        if (contentType2 != null) {
                            charset2 = contentType2.charset(UTF8);
                        }
                        if (!isPlaintext(buffer2)) {
                            this.logger.log(bodySize);
                            this.logger.log("<-- END HTTP (binary " + buffer2.size() + "-byte body omitted)");
                            return response;
                        }
                        if (contentLength != 0) {
                            this.logger.log(bodySize);
                            this.logger.log(buffer2.clone().readString(charset2));
                        }
                        if (gzippedLength != null) {
                            this.logger.log("<-- END HTTP (" + buffer2.size() + "-byte, " + gzippedLength + "-gzipped-byte body)");
                        } else {
                            this.logger.log("<-- END HTTP (" + buffer2.size() + str8);
                        }
                    }
                } else {
                    this.logger.log("<-- END HTTP");
                }
            }
            return response;
        } catch (Exception e) {
            this.logger.log("<-- HTTP FAILED: " + e);
            throw e;
        }
    }

    static boolean isPlaintext(Buffer buffer) {
        try {
            Buffer prefix = new Buffer();
            long byteCount = buffer.size() < 64 ? buffer.size() : 64L;
            buffer.copyTo(prefix, 0L, byteCount);
            for (int i = 0; i < 16; i++) {
                if (!prefix.exhausted()) {
                    int codePoint = prefix.readUtf8CodePoint();
                    if (Character.isISOControl(codePoint) && !Character.isWhitespace(codePoint)) {
                        return false;
                    }
                } else {
                    return true;
                }
            }
            return true;
        } catch (EOFException e) {
            return false;
        }
    }

    private boolean bodyHasUnknownEncoding(Headers headers) {
        String contentEncoding = headers.get(com.ding.rtc.http.HttpHeaders.CONTENT_ENCODING);
        return (contentEncoding == null || contentEncoding.equalsIgnoreCase("identity") || contentEncoding.equalsIgnoreCase("gzip")) ? false : true;
    }
}
