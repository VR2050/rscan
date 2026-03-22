package com.jbzd.media.movecartoons.bean;

/* loaded from: classes2.dex */
public class ResponseDataBean<T> {
    public T data;
    public String status;
    public String time;

    public T getData() {
        return this.data;
    }

    public String getStatus() {
        return this.status;
    }

    public String getTime() {
        return this.time;
    }

    public void setData(T t) {
        this.data = t;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setTime(String str) {
        this.time = str;
    }
}
