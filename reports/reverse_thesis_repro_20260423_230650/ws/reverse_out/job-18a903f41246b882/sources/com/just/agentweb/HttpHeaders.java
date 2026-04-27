package com.just.agentweb;

import android.net.Uri;
import android.text.TextUtils;
import androidx.collection.ArrayMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class HttpHeaders {
    private final Map<String, Map<String, String>> mHeaders = new ArrayMap();

    public static HttpHeaders create() {
        return new HttpHeaders();
    }

    HttpHeaders() {
    }

    public Map<String, String> getHeaders(String url) {
        String subUrl = subBaseUrl(url);
        if (this.mHeaders.get(subUrl) == null) {
            Map<String, String> headers = new ArrayMap<>();
            this.mHeaders.put(subUrl, headers);
            return headers;
        }
        return this.mHeaders.get(subUrl);
    }

    public void additionalHttpHeader(String url, String k, String v) {
        if (url == null) {
            return;
        }
        String url2 = subBaseUrl(url);
        Map<String, Map<String, String>> mHeaders = getHeaders();
        Map<String, String> headersMap = mHeaders.get(subBaseUrl(url2));
        if (headersMap == null) {
            headersMap = new ArrayMap();
        }
        headersMap.put(k, v);
        mHeaders.put(url2, headersMap);
    }

    public void additionalHttpHeaders(String url, Map<String, String> headers) {
        if (url == null) {
            return;
        }
        String subUrl = subBaseUrl(url);
        Map<String, Map<String, String>> mHeaders = getHeaders();
        Map<String, String> headersMap = headers;
        if (headersMap == null) {
            headersMap = new ArrayMap();
        }
        mHeaders.put(subUrl, headersMap);
    }

    public void removeHttpHeader(String url, String k) {
        if (url == null) {
            return;
        }
        String subUrl = subBaseUrl(url);
        Map<String, Map<String, String>> mHeaders = getHeaders();
        Map<String, String> headersMap = mHeaders.get(subUrl);
        if (headersMap != null) {
            headersMap.remove(k);
        }
    }

    public boolean isEmptyHeaders(String url) {
        Map<String, String> heads = getHeaders(subBaseUrl(url));
        return heads == null || heads.isEmpty();
    }

    public Map<String, Map<String, String>> getHeaders() {
        return this.mHeaders;
    }

    private String subBaseUrl(String originUrl) {
        if (TextUtils.isEmpty(originUrl)) {
            return originUrl;
        }
        try {
            Uri originUri = Uri.parse(originUrl);
            if (TextUtils.isEmpty(originUri.getScheme()) || TextUtils.isEmpty(originUri.getAuthority())) {
                return "";
            }
            return originUri.getScheme() + "://" + originUri.getAuthority();
        } catch (Throwable throwable) {
            throwable.printStackTrace();
            return "";
        }
    }

    public String toString() {
        return "HttpHeaders{mHeaders=" + this.mHeaders + '}';
    }
}
