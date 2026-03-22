package com.jbzd.media.movecartoons.bean.request;

/* loaded from: classes2.dex */
public class BaseRequestBody<T> {
    public T data;
    public String deviceId;
    public String token;

    public BaseRequestBody() {
    }

    public T getData() {
        return this.data;
    }

    public String getDeviceId() {
        return this.deviceId;
    }

    public String getToken() {
        return this.token;
    }

    public void setData(T t) {
        this.data = t;
    }

    public void setDeviceId(String str) {
        this.deviceId = str;
    }

    public void setToken(String str) {
        this.token = str;
    }

    public BaseRequestBody(String str, String str2, T t) {
        this.deviceId = str;
        this.token = str2;
        this.data = t;
    }
}
