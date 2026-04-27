package com.zhy.http.okhttp.builder;

import com.zhy.http.okhttp.builder.OkHttpRequestBuilder;
import com.zhy.http.okhttp.request.RequestCall;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public abstract class OkHttpRequestBuilder<T extends OkHttpRequestBuilder> {
    protected Map<String, String> headers;
    protected int id;
    protected Map<String, String> params;
    protected Object tag;
    protected String url;

    public abstract RequestCall build();

    public T id(int id) {
        this.id = id;
        return this;
    }

    public T url(String url) {
        this.url = url;
        return this;
    }

    public T tag(Object tag) {
        this.tag = tag;
        return this;
    }

    public T headers(Map<String, String> headers) {
        this.headers = headers;
        return this;
    }

    public T addHeader(String key, String val) {
        if (this.headers == null) {
            this.headers = new LinkedHashMap();
        }
        this.headers.put(key, val);
        return this;
    }
}
