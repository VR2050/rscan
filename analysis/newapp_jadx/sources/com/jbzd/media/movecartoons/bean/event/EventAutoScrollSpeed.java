package com.jbzd.media.movecartoons.bean.event;

/* loaded from: classes2.dex */
public class EventAutoScrollSpeed {
    private String speedNum;
    private String speedType;

    public EventAutoScrollSpeed(String str, String str2) {
        this.speedType = str;
        this.speedNum = str2;
    }

    public String getSpeedNum() {
        return this.speedNum;
    }

    public String getSpeedType() {
        return this.speedType;
    }

    public void setSpeedNum(String str) {
        this.speedNum = str;
    }

    public void setSpeedType(String str) {
        this.speedType = str;
    }
}
