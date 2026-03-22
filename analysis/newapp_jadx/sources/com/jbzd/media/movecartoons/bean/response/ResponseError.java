package com.jbzd.media.movecartoons.bean.response;

/* loaded from: classes2.dex */
public class ResponseError {
    private String error;
    private Integer errorCode;
    private String status;

    public String getError() {
        return this.error;
    }

    public Integer getErrorCode() {
        return this.errorCode;
    }

    public String getStatus() {
        return this.status;
    }

    public void setError(String str) {
        this.error = str;
    }

    public void setErrorCode(Integer num) {
        this.errorCode = num;
    }

    public void setStatus(String str) {
        this.status = str;
    }
}
