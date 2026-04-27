package org.webrtc.mozi;

import java.nio.ByteBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class RGBABuffer implements VideoFrame.Buffer {
    private final byte[] buffer;
    private final int height;
    private final RefCountDelegate refCountDelegate;
    private final int stride;
    private final int width;

    private static native void nativeCropAndScale(int i, int i2, int i3, int i4, int i5, int i6, byte[] bArr, int i7, int i8, int i9, ByteBuffer byteBuffer, int i10, ByteBuffer byteBuffer2, int i11, ByteBuffer byteBuffer3, int i12);

    public RGBABuffer(int width, int height, int stride, byte[] buffer, @Nullable Runnable releaseCallback) {
        this.width = width;
        this.height = height;
        this.stride = stride;
        this.buffer = buffer;
        this.refCountDelegate = new RefCountDelegate(releaseCallback);
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public int getWidth() {
        return this.width;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public int getHeight() {
        return this.height;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.I420Buffer toI420() {
        int i = this.width;
        int i2 = this.height;
        return (VideoFrame.I420Buffer) cropAndScale(0, 0, i, i2, i, i2);
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
        this.refCountDelegate.retain();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public void releaseBy(String trace) {
        this.refCountDelegate.release();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public String dump() {
        return null;
    }

    @Override // org.webrtc.mozi.RefCounted
    public boolean isReleased() {
        return this.refCountDelegate.isReleased();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer cropAndScale(int cropX, int cropY, int cropWidth, int cropHeight, int scaleWidth, int scaleHeight) {
        JavaI420Buffer newBuffer = JavaI420Buffer.allocate(scaleWidth, scaleHeight);
        nativeCropAndScale(cropX, cropY, cropWidth, cropHeight, scaleWidth, scaleHeight, this.buffer, this.width, this.height, this.stride, newBuffer.getDataY(), newBuffer.getStrideY(), newBuffer.getDataU(), newBuffer.getStrideU(), newBuffer.getDataV(), newBuffer.getStrideV());
        return newBuffer;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer alignWidth(int alignments) {
        return null;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer mirrorBuffer(boolean mirror) {
        return null;
    }
}
