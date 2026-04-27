package org.webrtc.mozi;

import android.graphics.Matrix;
import android.os.Handler;
import javax.annotation.Nullable;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class TextureBufferImpl implements VideoFrame.TextureBuffer {
    private TextureAlignmentDrawer alignmentDrawer;
    private final int height;
    private int id;
    private final RefCountDelegate refCountDelegate;
    private float[] textureMatrix;
    private int textureRotation;
    private final Handler toI420Handler;
    private Matrix transformMatrix;
    private VideoFrame.TextureBuffer.Type type;
    private final int width;
    private final YuvConverter yuvConverter;
    private final VideoFrame.Trace frameTrace = new VideoFrame.Trace("TextureBuffer");
    private McsConfigHelper configHelper = null;

    public TextureBufferImpl(int width, int height, VideoFrame.TextureBuffer.Type type, int id, Matrix transformMatrix, int textureRotation, Handler toI420Handler, YuvConverter yuvConverter, TextureAlignmentDrawer alignDrawer, @Nullable Runnable releaseCallback) {
        this.width = width;
        this.height = height;
        this.type = type;
        this.id = id;
        this.transformMatrix = transformMatrix;
        this.textureRotation = textureRotation;
        this.toI420Handler = toI420Handler;
        this.yuvConverter = yuvConverter;
        this.alignmentDrawer = alignDrawer;
        this.refCountDelegate = new RefCountDelegate(releaseCallback);
        if (WebrtcGrayConfig.sEnableCameraVideoFrameMonitor) {
            this.frameTrace.retain("Initialize");
        }
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public VideoFrame.TextureBuffer.Type getType() {
        return this.type;
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public int getTextureId() {
        return this.id;
    }

    public void setType(VideoFrame.TextureBuffer.Type type) {
        this.type = type;
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public void setTypeNative(int type) {
        if (type == 0) {
            this.type = VideoFrame.TextureBuffer.Type.OES;
        } else {
            this.type = VideoFrame.TextureBuffer.Type.RGB;
        }
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public void setTextureId(int id) {
        this.id = id;
    }

    public void setTransformMatrix(Matrix matrix) {
        this.transformMatrix = matrix;
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public Matrix getTransformMatrix() {
        return this.transformMatrix;
    }

    @Override // org.webrtc.mozi.VideoFrame.TextureBuffer
    public int getTextureRotation() {
        return this.textureRotation;
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
        return (VideoFrame.I420Buffer) ThreadUtils.invokeAtFrontUninterruptibly(this.toI420Handler, TextureBufferImpl$$Lambda$1.lambdaFactory$(this));
    }

    static /* synthetic */ VideoFrame.I420Buffer lambda$toI420$19(TextureBufferImpl textureBufferImpl) throws Exception {
        return textureBufferImpl.yuvConverter.convert(textureBufferImpl);
    }

    public VideoFrame.I420Buffer toI420ByRotation(int rotation) {
        return (VideoFrame.I420Buffer) ThreadUtils.invokeAtFrontUninterruptibly(this.toI420Handler, TextureBufferImpl$$Lambda$2.lambdaFactory$(this, rotation));
    }

    static /* synthetic */ VideoFrame.I420Buffer lambda$toI420ByRotation$20(TextureBufferImpl textureBufferImpl, int i) throws Exception {
        return textureBufferImpl.yuvConverter.convertByRotation(textureBufferImpl, i);
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
        if (WebrtcGrayConfig.sEnableCameraVideoFrameMonitor) {
            this.frameTrace.retain(trace);
        }
        this.refCountDelegate.retain();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public void releaseBy(String trace) {
        if (WebrtcGrayConfig.sEnableCameraVideoFrameMonitor) {
            this.frameTrace.release(trace);
        }
        this.refCountDelegate.release();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public String dump() {
        if (WebrtcGrayConfig.sEnableCameraVideoFrameMonitor) {
            return this.frameTrace.dump();
        }
        return "";
    }

    @Override // org.webrtc.mozi.RefCounted
    public boolean isReleased() {
        return this.refCountDelegate.isReleased();
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer cropAndScale(int cropX, int cropY, int cropWidth, int cropHeight, int scaleWidth, int scaleHeight) {
        Matrix cropAndScaleMatrix = new Matrix();
        int i = this.height;
        int cropYFromBottom = i - (cropY + cropHeight);
        cropAndScaleMatrix.preTranslate(cropX / this.width, cropYFromBottom / i);
        cropAndScaleMatrix.preScale(cropWidth / this.width, cropHeight / this.height);
        return applyTransformMatrix(cropAndScaleMatrix, scaleWidth, scaleHeight);
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer mirrorBuffer(boolean mirror) {
        Matrix mirrorMatrix = new Matrix();
        mirrorMatrix.preTranslate(0.5f, 0.5f);
        mirrorMatrix.preScale(-1.0f, 1.0f);
        mirrorMatrix.preTranslate(-0.5f, -0.5f);
        return applyTransformMatrix(mirrorMatrix, this.width, this.height);
    }

    public TextureBufferImpl applyTransformMatrix(Matrix transformMatrix, int newWidth, int newHeight) {
        Matrix newMatrix = new Matrix(this.transformMatrix);
        newMatrix.preConcat(transformMatrix);
        retain();
        return new TextureBufferImpl(newWidth, newHeight, this.type, this.id, newMatrix, this.textureRotation, this.toI420Handler, this.yuvConverter, this.alignmentDrawer, TextureBufferImpl$$Lambda$3.lambdaFactory$(this));
    }

    public TextureBufferImpl applyTransformMatrix(Matrix preTransformMatrix, Matrix postTransformMatrix, int newWidth, int newHeight) {
        Matrix newMatrix = new Matrix(this.transformMatrix);
        newMatrix.preConcat(preTransformMatrix);
        newMatrix.postConcat(postTransformMatrix);
        retain();
        return new TextureBufferImpl(newWidth, newHeight, this.type, this.id, newMatrix, this.textureRotation, this.toI420Handler, this.yuvConverter, this.alignmentDrawer, TextureBufferImpl$$Lambda$4.lambdaFactory$(this));
    }

    public void setAlignmentDrawer(TextureAlignmentDrawer drawer) {
        this.alignmentDrawer = drawer;
    }

    public void setConfigHelper(McsConfigHelper helper) {
        this.configHelper = helper;
    }

    @Override // org.webrtc.mozi.VideoFrame.Buffer
    public VideoFrame.Buffer alignWidth(int alignments) {
        if (this.alignmentDrawer == null) {
            throw new RuntimeException("TextureBufferImpl has null drawer!");
        }
        McsConfigHelper mcsConfigHelper = this.configHelper;
        if (mcsConfigHelper != null && mcsConfigHelper.getVideoCodecConfig().isFixTextureAlignmentEnabled()) {
            this.alignmentDrawer.alignDraw(this, alignments);
        } else {
            ThreadUtils.invokeAtFrontUninterruptibly(this.toI420Handler, TextureBufferImpl$$Lambda$5.lambdaFactory$(this, alignments));
        }
        retain();
        return new TextureBufferImpl(this.alignmentDrawer.getTextureWidth(), this.alignmentDrawer.getTextureHeight(), VideoFrame.TextureBuffer.Type.RGB, this.alignmentDrawer.getTextureId(), new Matrix(), this.textureRotation, this.toI420Handler, this.yuvConverter, this.alignmentDrawer, TextureBufferImpl$$Lambda$6.lambdaFactory$(this));
    }
}
