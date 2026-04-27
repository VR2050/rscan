package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelVideoFrame {
    byte[] buffer;
    int bufferType;
    int count;
    int height;
    boolean mirror;
    long offset0;
    long offset1;
    long offset2;
    int pixelFormat;
    int rotation;
    int stride0;
    int stride1;
    int stride2;
    int textureId;
    long timestamp;
    int width;

    PrivateRtcModelVideoFrame() {
    }

    public int getPixelFormat() {
        return this.pixelFormat;
    }

    public int getWidth() {
        return this.width;
    }

    public int getHeight() {
        return this.height;
    }

    public int getCount() {
        return this.count;
    }

    public long getOffset0() {
        return this.offset0;
    }

    public long getOffset1() {
        return this.offset1;
    }

    public long getOffset2() {
        return this.offset2;
    }

    public int getStride0() {
        return this.stride0;
    }

    public int getStride1() {
        return this.stride1;
    }

    public int getStride2() {
        return this.stride2;
    }

    public int getRotation() {
        return this.rotation;
    }

    public boolean isMirror() {
        return this.mirror;
    }

    public byte[] getBuffer() {
        return this.buffer;
    }

    public int getBufferType() {
        return this.bufferType;
    }

    public int getTextureId() {
        return this.textureId;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public void setPixelFormat(int pixelFormat) {
        this.pixelFormat = pixelFormat;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public void setOffset0(long offset0) {
        this.offset0 = offset0;
    }

    public void setOffset1(long offset1) {
        this.offset1 = offset1;
    }

    public void setOffset2(long offset2) {
        this.offset2 = offset2;
    }

    public void setStride0(int stride0) {
        this.stride0 = stride0;
    }

    public void setStride1(int stride1) {
        this.stride1 = stride1;
    }

    public void setStride2(int stride2) {
        this.stride2 = stride2;
    }

    public void setRotation(int rotation) {
        this.rotation = rotation;
    }

    public void setMirror(boolean mirror) {
        this.mirror = mirror;
    }

    public void setBuffer(byte[] buffer) {
        this.buffer = buffer;
    }

    public void setBufferType(int bufferType) {
        this.bufferType = bufferType;
    }

    public void setTextureId(int textureId) {
        this.textureId = textureId;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
