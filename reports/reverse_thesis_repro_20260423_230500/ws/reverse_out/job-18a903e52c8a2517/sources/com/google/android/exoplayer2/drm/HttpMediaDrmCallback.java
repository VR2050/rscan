package com.google.android.exoplayer2.drm;

import android.text.TextUtils;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.drm.ExoMediaDrm;
import com.google.android.exoplayer2.upstream.HttpDataSource;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;
import com.just.agentweb.AgentWebPermissions;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/* JADX INFO: loaded from: classes2.dex */
public final class HttpMediaDrmCallback implements MediaDrmCallback {
    private static final int MAX_MANUAL_REDIRECTS = 5;
    private final HttpDataSource.Factory dataSourceFactory;
    private final String defaultLicenseUrl;
    private final boolean forceDefaultLicenseUrl;
    private final Map<String, String> keyRequestProperties;

    public HttpMediaDrmCallback(String defaultLicenseUrl, HttpDataSource.Factory dataSourceFactory) {
        this(defaultLicenseUrl, false, dataSourceFactory);
    }

    public HttpMediaDrmCallback(String defaultLicenseUrl, boolean forceDefaultLicenseUrl, HttpDataSource.Factory dataSourceFactory) {
        this.dataSourceFactory = dataSourceFactory;
        this.defaultLicenseUrl = defaultLicenseUrl;
        this.forceDefaultLicenseUrl = forceDefaultLicenseUrl;
        this.keyRequestProperties = new HashMap();
    }

    public void setKeyRequestProperty(String name, String value) {
        Assertions.checkNotNull(name);
        Assertions.checkNotNull(value);
        synchronized (this.keyRequestProperties) {
            this.keyRequestProperties.put(name, value);
        }
    }

    public void clearKeyRequestProperty(String name) {
        Assertions.checkNotNull(name);
        synchronized (this.keyRequestProperties) {
            this.keyRequestProperties.remove(name);
        }
    }

    public void clearAllKeyRequestProperties() {
        synchronized (this.keyRequestProperties) {
            this.keyRequestProperties.clear();
        }
    }

    @Override // com.google.android.exoplayer2.drm.MediaDrmCallback
    public byte[] executeProvisionRequest(UUID uuid, ExoMediaDrm.ProvisionRequest request) throws IOException {
        String url = request.getDefaultUrl() + "&signedRequest=" + Util.fromUtf8Bytes(request.getData());
        return executePost(this.dataSourceFactory, url, Util.EMPTY_BYTE_ARRAY, null);
    }

    @Override // com.google.android.exoplayer2.drm.MediaDrmCallback
    public byte[] executeKeyRequest(UUID uuid, ExoMediaDrm.KeyRequest request) throws Exception {
        String contentType;
        String url = request.getLicenseServerUrl();
        if (this.forceDefaultLicenseUrl || TextUtils.isEmpty(url)) {
            url = this.defaultLicenseUrl;
        }
        Map<String, String> requestProperties = new HashMap<>();
        if (C.PLAYREADY_UUID.equals(uuid)) {
            contentType = "text/xml";
        } else {
            contentType = C.CLEARKEY_UUID.equals(uuid) ? "application/json" : "application/octet-stream";
        }
        requestProperties.put("Content-Type", contentType);
        if (C.PLAYREADY_UUID.equals(uuid)) {
            requestProperties.put("SOAPAction", "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense");
        }
        synchronized (this.keyRequestProperties) {
            requestProperties.putAll(this.keyRequestProperties);
        }
        return executePost(this.dataSourceFactory, url, request.getData(), requestProperties);
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0079 A[LOOP:1: B:9:0x002e->B:34:0x0079, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0081 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static byte[] executePost(com.google.android.exoplayer2.upstream.HttpDataSource.Factory r15, java.lang.String r16, byte[] r17, java.util.Map<java.lang.String, java.lang.String> r18) throws java.io.IOException {
        /*
            com.google.android.exoplayer2.upstream.HttpDataSource r1 = r15.createDataSource()
            if (r18 == 0) goto L2a
            java.util.Set r0 = r18.entrySet()
            java.util.Iterator r0 = r0.iterator()
        Le:
            boolean r2 = r0.hasNext()
            if (r2 == 0) goto L2a
            java.lang.Object r2 = r0.next()
            java.util.Map$Entry r2 = (java.util.Map.Entry) r2
            java.lang.Object r3 = r2.getKey()
            java.lang.String r3 = (java.lang.String) r3
            java.lang.Object r4 = r2.getValue()
            java.lang.String r4 = (java.lang.String) r4
            r1.setRequestProperty(r3, r4)
            goto Le
        L2a:
            r0 = 0
            r2 = r16
            r3 = r0
        L2e:
            com.google.android.exoplayer2.upstream.DataSpec r0 = new com.google.android.exoplayer2.upstream.DataSpec
            android.net.Uri r5 = android.net.Uri.parse(r2)
            r7 = 0
            r9 = 0
            r11 = -1
            r13 = 0
            r14 = 1
            r4 = r0
            r6 = r17
            r4.<init>(r5, r6, r7, r9, r11, r13, r14)
            com.google.android.exoplayer2.upstream.DataSourceInputStream r0 = new com.google.android.exoplayer2.upstream.DataSourceInputStream
            r0.<init>(r1, r4)
            r5 = r0
            byte[] r0 = com.google.android.exoplayer2.util.Util.toByteArray(r5)     // Catch: java.lang.Throwable -> L50 com.google.android.exoplayer2.upstream.HttpDataSource.InvalidResponseCodeException -> L52
            com.google.android.exoplayer2.util.Util.closeQuietly(r5)
            return r0
        L50:
            r0 = move-exception
            goto L82
        L52:
            r0 = move-exception
            r6 = r0
            r0 = r6
            int r6 = r0.responseCode     // Catch: java.lang.Throwable -> L50
            r7 = 307(0x133, float:4.3E-43)
            if (r6 == r7) goto L61
            int r6 = r0.responseCode     // Catch: java.lang.Throwable -> L50
            r7 = 308(0x134, float:4.32E-43)
            if (r6 != r7) goto L69
        L61:
            int r6 = r3 + 1
            r7 = 5
            if (r3 >= r7) goto L68
            r3 = 1
            goto L6c
        L68:
            r3 = r6
        L69:
            r6 = 0
            r6 = r3
            r3 = 0
        L6c:
            if (r3 == 0) goto L76
            java.lang.String r7 = getRedirectUrl(r0)     // Catch: java.lang.Throwable -> L73
            goto L77
        L73:
            r0 = move-exception
            r3 = r6
            goto L82
        L76:
            r7 = 0
        L77:
            if (r7 == 0) goto L80
            r2 = r7
            com.google.android.exoplayer2.util.Util.closeQuietly(r5)
            r3 = r6
            goto L2e
        L80:
            throw r0     // Catch: java.lang.Throwable -> L73
        L82:
            com.google.android.exoplayer2.util.Util.closeQuietly(r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.drm.HttpMediaDrmCallback.executePost(com.google.android.exoplayer2.upstream.HttpDataSource$Factory, java.lang.String, byte[], java.util.Map):byte[]");
    }

    private static String getRedirectUrl(HttpDataSource.InvalidResponseCodeException exception) {
        List<String> locationHeaders;
        Map<String, List<String>> headerFields = exception.headerFields;
        if (headerFields != null && (locationHeaders = headerFields.get(AgentWebPermissions.ACTION_LOCATION)) != null && !locationHeaders.isEmpty()) {
            return locationHeaders.get(0);
        }
        return null;
    }
}
