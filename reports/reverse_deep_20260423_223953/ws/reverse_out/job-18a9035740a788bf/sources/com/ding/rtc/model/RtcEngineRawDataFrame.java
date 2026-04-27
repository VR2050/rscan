package com.ding.rtc.model;

/* JADX INFO: loaded from: classes.dex */
public class RtcEngineRawDataFrame {
    public byte[] data;
    public int format = 1;
    public int width = 0;
    public int height = 0;
    public int strideY = 0;
    public int strideU = 0;
    public int strideV = 0;
    public int rotate = 0;
    public long timestamp = 0;

    public byte[] getData() {
        return this.data;
    }

    public int getFormat() {
        return this.format;
    }

    public int getWidth() {
        return this.width;
    }

    public int getHeight() {
        return this.height;
    }

    public int getStrideY() {
        return this.strideY;
    }

    public int getStrideU() {
        return this.strideU;
    }

    public int getStrideV() {
        return this.strideV;
    }

    public int getRotate() {
        return this.rotate;
    }

    public long getTimestamp() {
        return this.timestamp;
    }
}
