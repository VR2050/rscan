package org.webrtc.mozi;

import java.nio.ByteBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class JavaI420Buffer implements VideoFrame.I420Buffer {
    private final ByteBuffer dataU;
    private final ByteBuffer dataV;
    private final ByteBuffer dataY;
    private final int height;
    private final RefCountDelegate refCountDelegate;
    private final int strideU;
    private final int strideV;
    private final int strideY;
    private final int width;

    private static native void nativeCropAndScaleI420(ByteBuffer byteBuffer, int i, ByteBuffer byteBuffer2, int i2, ByteBuffer byteBuffer3, int i3, int i4, int i5, int i6, int i7, ByteBuffer byteBuffer4, int i8, ByteBuffer byteBuffer5, int i9, ByteBuffer byteBuffer6, int i10, int i11, int i12);

    private static native void nativeMirrorI420(ByteBuffer byteBuffer, int i, ByteBuffer byteBuffer2, int i2, ByteBuffer byteBuffer3, int i3, ByteBuffer byteBuffer4, int i4, ByteBuffer byteBuffer5, int i5, ByteBuffer byteBuffer6, int i6, int i7, int i8);

    private JavaI420Buffer(int width, int height, ByteBuffer dataY, int strideY, ByteBuffer dataU, int strideU, ByteBuffer dataV, int strideV, @Nullable Runnable releaseCallback) {
        this.width = width;
        this.height = height;
        this.dataY = dataY;
        this.dataU = dataU;
        this.dataV = dataV;
        this.strideY = strideY;
        this.strideU = strideU;
        this.strideV = strideV;
        this.refCountDelegate = new RefCountDelegate(releaseCallback);
    }

    private static void checkCapacity(ByteBuffer data, int width, int height, int stride) {
        int minCapacity = ((height - 1) * stride) + width;
        if (data.capacity() < minCapacity) {
            throw new IllegalArgumentException("Buffer must be at least " + minCapacity + " bytes, but was " + data.capacity());
        }
    }

    public static JavaI420Buffer wrap(int width, int height, ByteBuffer dataY, int strideY, ByteBuffer dataU, int strideU, ByteBuffer dataV, int strideV, @Nullable Runnable releaseCallback) {
        if (dataY == null || dataU == null || dataV == null) {
            throw new IllegalArgumentException("Data buffers cannot be null.");
        }
        if (!dataY.isDirect() || !dataU.isDirect() || !dataV.isDirect()) {
            throw new IllegalArgumentException("Data buffers must be direct byte buffers.");
        }
        ByteBuffer dataY2 = dataY.slice();
        ByteBuffer dataU2 = dataU.slice();
        ByteBuffer dataV2 = dataV.slice();
        int chromaWidth = (width + 1) / 2;
        int chromaHeight = (height + 1) / 2;
        checkCapacity(dataY2, width, height, strideY);
        checkCapacity(dataU2, chromaWidth, chromaHeight, strideU);
        checkCapacity(dataV2, chromaWidth, chromaHeight, strideV);
        return new JavaI420Buffer(width, height, dataY2, strideY, dataU2, strideU, dataV2, strideV, releaseCallback);
    }

    public static JavaI420Buffer allocate(int width, int height) {
        int chromaHeight = (height + 1) / 2;
        int strideUV = (width + 1) / 2;
        int uPos = 0 + (width * height);
        int vPos = uPos + (strideUV * chromaHeight);
        ByteBuffer buffer = JniCommon.nativeAllocateByteBuffer((width * height) + (strideUV * 2 * chromaHeight));
        buffer.position(0);
        buffer.limit(uPos);
        ByteBuffer dataY = buffer.slice();
        buffer.position(uPos);
        buffer.limit(vPos);
        ByteBuffer dataU = buffer.slice();
        buffer.position(vPos);
        buffer.limit((strideUV * chromaHeight) + vPos);
        ByteBuffer dataV = buffer.slice();
        return new JavaI420Buffer(width, height, dataY, width, dataU, strideUV, dataV, strideUV, JavaI420Buffer$$Lambda$1.lambdaFactory$(buffer));
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
        return cropAndScaleI420(this, cropX, cropY, cropWidth, cropHeight, scaleWidth, scaleHeight);
    }

    public static VideoFrame.Buffer cropAndScaleI420(VideoFrame.I420Buffer buffer, int cropX, int cropY, int cropWidth, int cropHeight, int scaleWidth, int scaleHeight) {
        if (cropWidth == scaleWidth && cropHeight == scaleHeight) {
            ByteBuffer dataY = buffer.getDataY();
            ByteBuffer dataU = buffer.getDataU();
            ByteBuffer dataV = buffer.getDataV();
            dataY.position(cropX + (buffer.getStrideY() * cropY));
            dataU.position((cropX / 2) + ((cropY / 2) * buffer.getStrideU()));
            dataV.position((cropX / 2) + ((cropY / 2) * buffer.getStrideV()));
            buffer.retain();
            ByteBuffer byteBufferSlice = dataY.slice();
            int strideY = buffer.getStrideY();
            ByteBuffer byteBufferSlice2 = dataU.slice();
            int strideU = buffer.getStrideU();
            ByteBuffer byteBufferSlice3 = dataV.slice();
            int strideV = buffer.getStrideV();
            buffer.getClass();
            return wrap(scaleWidth, scaleHeight, byteBufferSlice, strideY, byteBufferSlice2, strideU, byteBufferSlice3, strideV, JavaI420Buffer$$Lambda$4.lambdaFactory$(buffer));
        }
        JavaI420Buffer newBuffer = allocate(scaleWidth, scaleHeight);
        nativeCropAndScaleI420(buffer.getDataY(), buffer.getStrideY(), buffer.getDataU(), buffer.getStrideU(), buffer.getDataV(), buffer.getStrideV(), cropX, cropY, cropWidth, cropHeight, newBuffer.getDataY(), newBuffer.getStrideY(), newBuffer.getDataU(), newBuffer.getStrideU(), newBuffer.getDataV(), newBuffer.getStrideV(), scaleWidth, scaleHeight);
        return newBuffer;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer alignWidth(int alignments) {
        int newWidth = (this.width + (alignments - 1)) & (~(alignments - 1));
        JavaI420Buffer newBuffer = allocate(newWidth, this.height);
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
        JavaI420Buffer newBuffer = allocate(this.width, this.height);
        nativeMirrorI420(getDataY(), getStrideY(), getDataU(), getStrideU(), getDataV(), getStrideV(), newBuffer.getDataY(), newBuffer.getStrideY(), newBuffer.getDataU(), newBuffer.getStrideU(), newBuffer.getDataV(), newBuffer.getStrideV(), this.width, this.height);
        return newBuffer;
    }
}
