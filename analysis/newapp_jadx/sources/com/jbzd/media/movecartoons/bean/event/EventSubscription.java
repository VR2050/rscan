package com.jbzd.media.movecartoons.bean.event;

/* loaded from: classes2.dex */
public class EventSubscription {
    private String status;
    private String userId;

    public EventSubscription() {
    }

    public String getStatus() {
        return this.status;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public EventSubscription(String str, String str2) {
        this.userId = str;
        this.status = str2;
    }
}
