package org.webrtc.mozi;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class WrappedNativeI420Buffer implements VideoFrame.I420Buffer {
    private final ByteBuffer dataU;
    private final ByteBuffer dataV;
    private final ByteBuffer dataY;
    private final int height;
    private final long nativeBuffer;
    private final AtomicInteger refCount = new AtomicInteger();
    private final int strideU;
    private final int strideV;
    private final int strideY;
    private final int width;

    WrappedNativeI420Buffer(int width, int height, ByteBuffer dataY, int strideY, ByteBuffer dataU, int strideU, ByteBuffer dataV, int strideV, long nativeBuffer) {
        this.width = width;
        this.height = height;
        this.dataY = dataY;
        this.strideY = strideY;
        this.dataU = dataU;
        this.strideU = strideU;
        this.dataV = dataV;
        this.strideV = strideV;
        this.nativeBuffer = nativeBuffer;
        retain();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public int getWidth() {
        return this.width;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public int getHeight() {
        return this.height;
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public ByteBuffer getDataY() {
        return this.dataY.slice();
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public ByteBuffer getDataU() {
        return this.dataU.slice();
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public ByteBuffer getDataV() {
        return this.dataV.slice();
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public int getStrideY() {
        return this.strideY;
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public int getStrideU() {
        return this.strideU;
    }

    @Override // org.webrtc.mozi.VideoFrame.I420Buffer
    public int getStrideV() {
        return this.strideV;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.I420Buffer toI420() {
        retain();
        return this;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer, org.webrtc.mozi.RefCounted
    public void retain() {
        retainBy("Unknown");
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer, org.webrtc.mozi.RefCounted
    public void release() {
        releaseBy("Unknown");
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public void retainBy(String trace) {
        this.refCount.incrementAndGet();
        JniCommon.nativeAddRef(this.nativeBuffer);
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public void releaseBy(String trace) {
        this.refCount.decrementAndGet();
        JniCommon.nativeReleaseRef(this.nativeBuffer);
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public String dump() {
        return null;
    }

    @Override // org.webrtc.mozi.RefCounted
    public boolean isReleased() {
        return this.refCount.get() <= 0;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer cropAndScale(int cropX, int cropY, int cropWidth, int cropHeight, int scaleWidth, int scaleHeight) {
        return JavaI420Buffer.cropAndScaleI420(this, cropX, cropY, cropWidth, cropHeight, scaleWidth, scaleHeight);
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer alignWidth(int alignments) {
        int newWidth = (this.width + (alignments - 1)) & (~(alignments - 1));
        JavaI420Buffer newBuffer = JavaI420Buffer.allocate(newWidth, this.height);
        ByteBuffer dataY = getDataY();
        int strideY = getStrideY();
        ByteBuffer dataU = getDataU();
        int strideU = getStrideU();
        ByteBuffer dataV = getDataV();
        int strideV = getStrideV();
        ByteBuffer dataY2 = newBuffer.getDataY();
        int strideY2 = newBuffer.getStrideY();
        ByteBuffer dataU2 = newBuffer.getDataU();
        int strideU2 = newBuffer.getStrideU();
        ByteBuffer dataV2 = newBuffer.getDataV();
        int strideV2 = newBuffer.getStrideV();
        int i = this.width;
        int newWidth2 = this.height;
        YuvHelper.I420Copy(dataY, strideY, dataU, strideU, dataV, strideV, dataY2, strideY2, dataU2, strideU2, dataV2, strideV2, i, newWidth2);
        return newBuffer;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer mirrorBuffer(boolean mirror) {
        return null;
    }
}
