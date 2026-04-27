package com.ding.rtc.model;

import android.graphics.Matrix;
import com.ding.rtc.DingRtcEngine;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.JavaScreenCapturer;
import org.webrtc.mozi.NV21Buffer;
import org.webrtc.mozi.TextureBufferImpl;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes.dex */
public class RtcEngineVideoFrame {
    private byte[] data;
    private EglBase.Context eglBaseContext;
    private NV21Buffer nv21Buffer;
    private TextureBufferImpl textureBuffer;
    private long dataFrameY = 0;
    private long dataFrameU = 0;
    private long dataFrameV = 0;
    private int format = 1;
    private int width = 0;
    private int height = 0;
    private int strideY = 0;
    private int strideU = 0;
    private int strideV = 0;
    private int offsetY = 0;
    private int offsetU = 0;
    private int offsetV = 0;
    private int rotate = 0;
    private boolean mirror = false;
    private long extraData = 0;

    private RtcEngineVideoFrame() {
    }

    public void setDataFrameY(long dataFrameY) {
        this.dataFrameY = dataFrameY;
    }

    public void setDataFrameU(long dataFrameU) {
        this.dataFrameU = dataFrameU;
    }

    public void setDataFrameV(long dataFrameV) {
        this.dataFrameV = dataFrameV;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public void setFormat(int format) {
        this.format = format;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public void setStrideY(int strideY) {
        this.strideY = strideY;
    }

    public void setStrideU(int strideU) {
        this.strideU = strideU;
    }

    public void setStrideV(int strideV) {
        this.strideV = strideV;
    }

    public void setOffsetY(int offsetY) {
        this.offsetY = offsetY;
    }

    public void setOffsetU(int offsetU) {
        this.offsetU = offsetU;
    }

    public void setOffsetV(int offsetV) {
        this.offsetV = offsetV;
    }

    public void setRotate(int rotate) {
        this.rotate = rotate;
    }

    public void setMirror(boolean mirror) {
        this.mirror = mirror;
    }

    public void setExtraData(long extraData) {
        this.extraData = extraData;
    }

    public void setTextureBuffer(TextureBufferImpl textureBuffer) {
        this.textureBuffer = textureBuffer;
    }

    public void setNV21Buffer(NV21Buffer nv21Buffer) {
        this.nv21Buffer = nv21Buffer;
    }

    public void setTextureId(int id) {
        this.textureBuffer.setTextureId(id);
    }

    public void setType(VideoFrame.TextureBuffer.Type type) {
        this.textureBuffer.setType(type);
    }

    public void setTransformMatrix(Matrix matrix) {
        this.textureBuffer.setTransformMatrix(matrix);
    }

    public int getRotationByTransformMatrix() {
        TextureBufferImpl textureBufferImpl = this.textureBuffer;
        if (textureBufferImpl != null) {
            Matrix transformMatrix = textureBufferImpl.getTransformMatrix();
            float[] values = new float[9];
            transformMatrix.getValues(values);
            if (values[1] > 0.0f) {
                return JavaScreenCapturer.DEGREE_270;
            }
            return 90;
        }
        return 0;
    }

    public int getTextureId() {
        return this.textureBuffer.getTextureId();
    }

    public void setEglBaseContext(EglBase.Context eglBaseContext) {
        this.eglBaseContext = eglBaseContext;
    }

    public DingRtcEngine.DingRtcVideoSample convert() {
        DingRtcEngine.DingRtcVideoSample sample = new DingRtcEngine.DingRtcVideoSample();
        sample.dataFrameY = this.dataFrameY;
        sample.dataFrameU = this.dataFrameU;
        sample.dataFrameV = this.dataFrameV;
        NV21Buffer nV21Buffer = this.nv21Buffer;
        if (nV21Buffer != null) {
            sample.data = nV21Buffer.getData();
        } else {
            sample.data = this.data;
        }
        sample.format = DingRtcEngine.DingRtcVideoFormat.fromNativeIndex(this.format);
        sample.width = this.width;
        sample.height = this.height;
        sample.strideY = this.strideY;
        sample.strideU = this.strideU;
        sample.strideV = this.strideV;
        sample.offsetY = this.offsetY;
        sample.offsetU = this.offsetU;
        sample.offsetV = this.offsetV;
        sample.rotate = this.rotate;
        sample.mirror = this.mirror;
        sample.extraData = this.extraData;
        if (this.format == 7) {
            TextureBufferImpl textureBufferImpl = this.textureBuffer;
            if (textureBufferImpl != null) {
                sample.textureId = textureBufferImpl.getTextureId();
                sample.type = this.textureBuffer.getType();
                sample.transformMatrix = this.textureBuffer.getTransformMatrix();
            }
        } else {
            this.textureBuffer = null;
        }
        sample.eglBaseContext = this.eglBaseContext;
        return sample;
    }
}
