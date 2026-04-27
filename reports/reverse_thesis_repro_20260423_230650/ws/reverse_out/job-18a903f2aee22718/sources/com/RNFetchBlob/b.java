package com.RNFetchBlob;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public Boolean f5758a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public String f5759b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public String f5760c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public ReadableMap f5761d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public Boolean f5762e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public Boolean f5763f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public String f5764g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public String f5765h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public Boolean f5766i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public Boolean f5767j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public long f5768k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public Boolean f5769l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public Boolean f5770m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public ReadableArray f5771n;

    b(ReadableMap readableMap) {
        Boolean bool = Boolean.FALSE;
        this.f5763f = bool;
        Boolean bool2 = Boolean.TRUE;
        this.f5767j = bool2;
        this.f5768k = 60000L;
        this.f5769l = bool;
        this.f5770m = bool2;
        this.f5771n = null;
        if (readableMap == null) {
            return;
        }
        this.f5758a = Boolean.valueOf(readableMap.hasKey("fileCache") ? readableMap.getBoolean("fileCache") : false);
        this.f5759b = readableMap.hasKey("path") ? readableMap.getString("path") : null;
        this.f5760c = readableMap.hasKey("appendExt") ? readableMap.getString("appendExt") : "";
        this.f5762e = Boolean.valueOf(readableMap.hasKey("trusty") ? readableMap.getBoolean("trusty") : false);
        this.f5763f = Boolean.valueOf(readableMap.hasKey("wifiOnly") ? readableMap.getBoolean("wifiOnly") : false);
        if (readableMap.hasKey("addAndroidDownloads")) {
            this.f5761d = readableMap.getMap("addAndroidDownloads");
        }
        if (readableMap.hasKey("binaryContentTypes")) {
            this.f5771n = readableMap.getArray("binaryContentTypes");
        }
        String str = this.f5759b;
        if (str != null && str.toLowerCase().contains("?append=true")) {
            this.f5767j = bool;
        }
        if (readableMap.hasKey("overwrite")) {
            this.f5767j = Boolean.valueOf(readableMap.getBoolean("overwrite"));
        }
        if (readableMap.hasKey("followRedirect")) {
            this.f5770m = Boolean.valueOf(readableMap.getBoolean("followRedirect"));
        }
        this.f5764g = readableMap.hasKey("key") ? readableMap.getString("key") : null;
        this.f5765h = readableMap.hasKey("contentType") ? readableMap.getString("contentType") : null;
        this.f5769l = Boolean.valueOf(readableMap.hasKey("increment") ? readableMap.getBoolean("increment") : false);
        this.f5766i = Boolean.valueOf(readableMap.hasKey("auto") ? readableMap.getBoolean("auto") : false);
        if (readableMap.hasKey("timeout")) {
            this.f5768k = readableMap.getInt("timeout");
        }
    }
}
