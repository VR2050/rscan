package org.webrtc.mozi;

import android.graphics.Matrix;
import android.graphics.Point;
import android.opengl.GLES20;
import java.nio.ByteBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.RendererCommon;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class RTCVideoEglDrawer extends VideoFrameDrawer {
    private static final float[] srcPoints = {0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f};
    private DrawRecord lastDrawRecord;
    private VideoFrame lastI420Frame;
    private final float[] dstPoints = new float[6];
    private final Point renderSize = new Point();
    private final YuvUploader yuvUploader = new YuvUploader(null);
    private final Matrix renderMatrix = new Matrix();

    private static class YuvUploader {
        private ByteBuffer copyBuffer;
        private int[] yuvTextures;

        private YuvUploader() {
        }

        /* synthetic */ YuvUploader(AnonymousClass1 x0) {
            this();
        }

        public int[] uploadYuvData(int width, int height, int[] strides, ByteBuffer[] planes) {
            ByteBuffer packedByteBuffer;
            ByteBuffer byteBuffer;
            int[] planeWidths = {width, width / 2, width / 2};
            int[] planeHeights = {height, height / 2, height / 2};
            int copyCapacityNeeded = 0;
            for (int i = 0; i < 3; i++) {
                if (strides[i] > planeWidths[i]) {
                    copyCapacityNeeded = Math.max(copyCapacityNeeded, planeWidths[i] * planeHeights[i]);
                }
            }
            if (copyCapacityNeeded > 0 && ((byteBuffer = this.copyBuffer) == null || byteBuffer.capacity() < copyCapacityNeeded)) {
                this.copyBuffer = ByteBuffer.allocateDirect(copyCapacityNeeded);
            }
            if (this.yuvTextures == null) {
                this.yuvTextures = new int[3];
                for (int i2 = 0; i2 < 3; i2++) {
                    this.yuvTextures[i2] = GlUtil.generateTexture(3553);
                }
            }
            for (int i3 = 0; i3 < 3; i3++) {
                GLES20.glActiveTexture(33984 + i3);
                GLES20.glBindTexture(3553, this.yuvTextures[i3]);
                if (strides[i3] != planeWidths[i3]) {
                    YuvHelper.copyPlane(planes[i3], strides[i3], this.copyBuffer, planeWidths[i3], planeWidths[i3], planeHeights[i3]);
                    packedByteBuffer = this.copyBuffer;
                } else {
                    packedByteBuffer = planes[i3];
                }
                GLES20.glTexImage2D(3553, 0, 6409, planeWidths[i3], planeHeights[i3], 0, 6409, 5121, packedByteBuffer);
            }
            return this.yuvTextures;
        }

        public int[] uploadFromBuffer(VideoFrame.I420Buffer buffer) {
            int[] strides = {buffer.getStrideY(), buffer.getStrideU(), buffer.getStrideV()};
            ByteBuffer[] planes = {buffer.getDataY(), buffer.getDataU(), buffer.getDataV()};
            return uploadYuvData(buffer.getWidth(), buffer.getHeight(), strides, planes);
        }

        public int[] getYuvTextures() {
            return this.yuvTextures;
        }

        public void release() {
            this.copyBuffer = null;
            int[] iArr = this.yuvTextures;
            if (iArr != null) {
                GLES20.glDeleteTextures(3, iArr, 0);
                this.yuvTextures = null;
            }
        }
    }

    private static abstract class DrawRecord {
        private int frameExtraRotation;
        private int frameHeight;
        private int frameRotation;
        private int frameWidth;
        private final boolean needFlipY;
        private volatile boolean isValid = false;
        private final Matrix frameMatrix = new Matrix();
        private final Matrix renderMatrix = new Matrix();
        private final float[] dstPoints = new float[6];
        private final Point renderSize = new Point();

        protected abstract void onRedraw(RendererCommon.GlDrawer glDrawer, float[] fArr, Matrix matrix, int i, int i2, int i3, int i4, int i5, int i6);

        protected DrawRecord(boolean needFlipY) {
            this.needFlipY = needFlipY;
        }

        void setValid(boolean valid) {
            this.isValid = valid;
        }

        void redraw(RendererCommon.GlDrawer drawer, float[] verticesCoord, boolean mirror, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
            RTCVideoEglDrawer.calculateFrameMatrix(this.frameMatrix, this.frameRotation, this.frameExtraRotation, mirror);
            RTCVideoEglDrawer.calculateTransformedRenderSize(this.frameWidth, this.frameHeight, this.frameMatrix, this.dstPoints, this.renderSize);
            RTCVideoEglDrawer.calculateTransformedRenderMatrix(this.renderMatrix, this.needFlipY, this.frameRotation, this.frameMatrix);
            onRedraw(drawer, verticesCoord, this.renderMatrix, this.renderSize.x, this.renderSize.y, viewportX, viewportY, viewportWidth, viewportHeight);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void record(int frameWidth, int frameHeight, int frameRotation, int frameExtraRotation) {
            this.frameWidth = frameWidth;
            this.frameHeight = frameHeight;
            this.frameRotation = frameRotation;
            this.frameExtraRotation = frameExtraRotation;
            setValid(true);
        }

        protected boolean canRedraw() {
            return this.isValid && this.frameWidth > 0 && this.frameHeight > 0;
        }
    }

    private static class TextureDrawRecord extends DrawRecord {
        private Matrix bufferMatrix;
        private final Matrix finalMatrix;
        private int textureId;
        private VideoFrame.TextureBuffer.Type textureType;

        TextureDrawRecord() {
            super(false);
            this.finalMatrix = new Matrix();
        }

        void record(int textureId, VideoFrame.TextureBuffer.Type frameType, Matrix bufferMatrix, int frameWidth, int frameHeight, int frameRotation, int frameExtraRotation) {
            this.textureId = textureId;
            this.textureType = frameType;
            this.bufferMatrix = bufferMatrix;
            record(frameWidth, frameHeight, frameRotation, frameExtraRotation);
        }

        @Override // org.webrtc.mozi.RTCVideoEglDrawer.DrawRecord
        protected boolean canRedraw() {
            int i;
            return super.canRedraw() && (i = this.textureId) != 0 && GLES20.glIsTexture(i);
        }

        @Override // org.webrtc.mozi.RTCVideoEglDrawer.DrawRecord
        protected void onRedraw(RendererCommon.GlDrawer drawer, float[] verticesCoord, Matrix renderMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
            this.finalMatrix.set(this.bufferMatrix);
            this.finalMatrix.preConcat(renderMatrix);
            float[] finalGlMatrix = RendererCommon.convertMatrixFromAndroidGraphicsMatrix(this.finalMatrix);
            synchronized (EglBase.lock) {
                if (this.textureType == VideoFrame.TextureBuffer.Type.RGB) {
                    drawer.drawRgb2(this.textureId, verticesCoord, finalGlMatrix, frameWidth, frameHeight, viewportX, viewportY, viewportWidth, viewportHeight);
                } else {
                    drawer.drawOes2(this.textureId, verticesCoord, finalGlMatrix, frameWidth, frameHeight, viewportX, viewportY, viewportWidth, viewportHeight);
                }
            }
            Logging.d("TextureDrawRecord", "onRedraw end");
        }
    }

    private static class YuvDrawRecord extends DrawRecord {
        private int colorSpace;
        private int[] yuvTextures;

        YuvDrawRecord() {
            super(true);
        }

        void record(int[] yuvTextures, int frameWidth, int frameHeight, int frameRotation, int frameExtraRotation, int colorSpace) {
            this.yuvTextures = yuvTextures;
            this.colorSpace = colorSpace;
            record(frameWidth, frameHeight, frameRotation, frameExtraRotation);
        }

        @Override // org.webrtc.mozi.RTCVideoEglDrawer.DrawRecord
        protected boolean canRedraw() {
            int[] iArr;
            if (!super.canRedraw() || (iArr = this.yuvTextures) == null) {
                return false;
            }
            for (int textureId : iArr) {
                if (textureId == 0 || !GLES20.glIsTexture(textureId)) {
                    return false;
                }
            }
            return true;
        }

        @Override // org.webrtc.mozi.RTCVideoEglDrawer.DrawRecord
        protected void onRedraw(RendererCommon.GlDrawer drawer, float[] verticesCoord, Matrix renderMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
            drawer.drawYuv2(this.yuvTextures, verticesCoord, RendererCommon.convertMatrixFromAndroidGraphicsMatrix(renderMatrix), frameWidth, frameHeight, viewportX, viewportY, viewportWidth, viewportHeight, this.colorSpace);
        }
    }

    private static void drawTextureInternal(RendererCommon.GlDrawer drawer, VideoFrame.TextureBuffer buffer, Matrix renderMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        Matrix finalMatrix = new Matrix(buffer.getTransformMatrix());
        finalMatrix.preConcat(renderMatrix);
        float[] finalGlMatrix = RendererCommon.convertMatrixFromAndroidGraphicsMatrix(finalMatrix);
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$VideoFrame$TextureBuffer$Type[buffer.getType().ordinal()];
        if (i == 1) {
            drawer.drawOes(buffer.getTextureId(), finalGlMatrix, frameWidth, frameHeight, viewportX, viewportY, viewportWidth, viewportHeight);
        } else {
            if (i == 2) {
                drawer.drawRgb(buffer.getTextureId(), finalGlMatrix, frameWidth, frameHeight, viewportX, viewportY, viewportWidth, viewportHeight);
                return;
            }
            throw new RuntimeException("Unknown texture type.");
        }
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.RTCVideoEglDrawer$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$mozi$VideoFrame$TextureBuffer$Type;

        static {
            int[] iArr = new int[VideoFrame.TextureBuffer.Type.values().length];
            $SwitchMap$org$webrtc$mozi$VideoFrame$TextureBuffer$Type = iArr;
            try {
                iArr[VideoFrame.TextureBuffer.Type.OES.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoFrame$TextureBuffer$Type[VideoFrame.TextureBuffer.Type.RGB.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    private static int distance(float x0, float y0, float x1, float y1) {
        return (int) Math.round(Math.hypot(x1 - x0, y1 - y0));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void calculateTransformedRenderSize(int frameWidth, int frameHeight, Matrix additionalRenderMatrix, float[] dstPoints, Point outSize) {
        if (additionalRenderMatrix == null) {
            outSize.x = frameWidth;
            outSize.y = frameHeight;
            return;
        }
        additionalRenderMatrix.mapPoints(dstPoints, srcPoints);
        for (int i = 0; i < 3; i++) {
            int i2 = (i * 2) + 0;
            dstPoints[i2] = dstPoints[i2] * frameWidth;
            int i3 = (i * 2) + 1;
            dstPoints[i3] = dstPoints[i3] * frameHeight;
        }
        outSize.x = distance(dstPoints[0], dstPoints[1], dstPoints[2], dstPoints[3]);
        outSize.y = distance(dstPoints[0], dstPoints[1], dstPoints[4], dstPoints[5]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void calculateTransformedRenderMatrix(Matrix renderMatrix, boolean needFlipY, int frameRotation, Matrix additionalRenderMatrix) {
        renderMatrix.reset();
        renderMatrix.preTranslate(0.5f, 0.5f);
        if (needFlipY) {
            renderMatrix.preScale(1.0f, -1.0f);
        }
        renderMatrix.preTranslate(-0.5f, -0.5f);
        if (additionalRenderMatrix != null) {
            renderMatrix.preConcat(additionalRenderMatrix);
        }
    }

    private static void calculateFrameMatrixFitToViewport(Matrix frameMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight, boolean mirror) {
        float scaleX;
        float scaleY;
        float frameAspectRatio = frameWidth / frameHeight;
        float drawnAspectRatio = viewportWidth / viewportHeight;
        if (frameAspectRatio > drawnAspectRatio) {
            scaleX = drawnAspectRatio / frameAspectRatio;
            scaleY = 1.0f;
        } else {
            scaleX = 1.0f;
            scaleY = frameAspectRatio / drawnAspectRatio;
        }
        frameMatrix.reset();
        frameMatrix.preTranslate(0.5f, 0.5f);
        if (mirror) {
            frameMatrix.preScale(-1.0f, 1.0f);
        }
        frameMatrix.preScale(scaleX, scaleY);
        frameMatrix.preTranslate(-0.5f, -0.5f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void calculateFrameMatrix(Matrix frameMatrix, int frameRotation, int frameExtraRotation, boolean mirror) {
        frameMatrix.reset();
        frameMatrix.preTranslate(0.5f, 0.5f);
        if (mirror) {
            if (frameExtraRotation == 90 || frameExtraRotation == 270) {
                frameMatrix.preRotate(frameRotation);
                frameMatrix.preScale(-1.0f, 1.0f);
            } else {
                frameMatrix.preScale(-1.0f, 1.0f);
                frameMatrix.preRotate(frameRotation);
            }
        } else {
            frameMatrix.preRotate(frameRotation);
        }
        frameMatrix.preTranslate(-0.5f, -0.5f);
    }

    @Override // org.webrtc.mozi.VideoFrameDrawer
    public void drawFrame(VideoFrame frame, RendererCommon.GlDrawer drawer, Matrix additionalRenderMatrix, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        int width = frame.getRotatedWidth();
        int height = frame.getRotatedHeight();
        int rotation = frame.getRotation();
        boolean isTextureFrame = frame.getBuffer() instanceof VideoFrame.TextureBuffer;
        calculateTransformedRenderSize(width, height, additionalRenderMatrix, this.dstPoints, this.renderSize);
        calculateTransformedRenderMatrix(this.renderMatrix, !isTextureFrame, rotation, additionalRenderMatrix);
        if (isTextureFrame) {
            this.lastI420Frame = null;
            VideoFrame.TextureBuffer textureBuffer = (VideoFrame.TextureBuffer) frame.getBuffer();
            drawTextureInternal(drawer, textureBuffer, this.renderMatrix, this.renderSize.x, this.renderSize.y, viewportX, viewportY, viewportWidth, viewportHeight);
            recordTextureDraw(textureBuffer.getTextureId(), textureBuffer.getType(), textureBuffer.getTransformMatrix(), width, height, rotation, frame.getExtraRotation());
            return;
        }
        if (frame != this.lastI420Frame) {
            this.lastI420Frame = frame;
            VideoFrame.I420Buffer i420Buffer = frame.getBuffer().toI420();
            this.yuvUploader.uploadFromBuffer(i420Buffer);
            i420Buffer.release();
        }
        drawer.drawYuv(this.yuvUploader.getYuvTextures(), RendererCommon.convertMatrixFromAndroidGraphicsMatrix(this.renderMatrix), this.renderSize.x, this.renderSize.y, viewportX, viewportY, viewportWidth, viewportHeight);
        recordYuvDraw(this.yuvUploader.getYuvTextures(), width, height, rotation, frame.getExtraRotation(), frame.getColorspace());
    }

    @Override // org.webrtc.mozi.VideoFrameDrawer
    public void drawFrame(VideoFrame frame, RendererCommon.GlDrawer drawer, float[] verticesCoord, @Nullable Matrix additionalRenderMatrix, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        int width = frame.getRotatedWidth();
        int height = frame.getRotatedHeight();
        int rotation = frame.getRotation();
        boolean isTextureFrame = frame.getBuffer() instanceof VideoFrame.TextureBuffer;
        calculateTransformedRenderSize(width, height, additionalRenderMatrix, this.dstPoints, this.renderSize);
        calculateTransformedRenderMatrix(this.renderMatrix, !isTextureFrame, rotation, additionalRenderMatrix);
        if (isTextureFrame) {
            this.lastI420Frame = null;
            VideoFrame.TextureBuffer textureBuffer = (VideoFrame.TextureBuffer) frame.getBuffer();
            drawTexture2(drawer, textureBuffer, verticesCoord, this.renderMatrix, this.renderSize.x, this.renderSize.y, viewportX, viewportY, viewportWidth, viewportHeight);
            recordTextureDraw(textureBuffer.getTextureId(), textureBuffer.getType(), textureBuffer.getTransformMatrix(), width, height, rotation, frame.getExtraRotation());
            return;
        }
        if (frame != this.lastI420Frame) {
            this.lastI420Frame = frame;
            VideoFrame.I420Buffer i420Buffer = frame.getBuffer().toI420();
            this.yuvUploader.uploadFromBuffer(i420Buffer);
            i420Buffer.release();
        }
        drawer.drawYuv2(this.yuvUploader.getYuvTextures(), verticesCoord, RendererCommon.convertMatrixFromAndroidGraphicsMatrix(this.renderMatrix), this.renderSize.x, this.renderSize.y, viewportX, viewportY, viewportWidth, viewportHeight, frame.getColorspace());
        recordYuvDraw(this.yuvUploader.getYuvTextures(), width, height, rotation, frame.getExtraRotation(), frame.getColorspace());
    }

    private void recordTextureDraw(int textureId, VideoFrame.TextureBuffer.Type textureType, Matrix bufferMatrix, int frameWidth, int frameHeight, int frameRotation, int frameExtraRotation) {
        TextureDrawRecord textureDrawRecord;
        DrawRecord drawRecord = this.lastDrawRecord;
        if (drawRecord instanceof TextureDrawRecord) {
            textureDrawRecord = (TextureDrawRecord) drawRecord;
        } else {
            textureDrawRecord = new TextureDrawRecord();
            this.lastDrawRecord = textureDrawRecord;
        }
        textureDrawRecord.record(textureId, textureType, bufferMatrix, frameWidth, frameHeight, frameRotation, frameExtraRotation);
    }

    private void recordYuvDraw(int[] yuvTextures, int frameWidth, int frameHeight, int frameRotation, int frameExtraRotation, int colorSpace) {
        YuvDrawRecord yuvDrawRecord;
        DrawRecord drawRecord = this.lastDrawRecord;
        if (drawRecord instanceof YuvDrawRecord) {
            yuvDrawRecord = (YuvDrawRecord) drawRecord;
        } else {
            yuvDrawRecord = new YuvDrawRecord();
            this.lastDrawRecord = yuvDrawRecord;
        }
        yuvDrawRecord.record(yuvTextures, frameWidth, frameHeight, frameRotation, frameExtraRotation, colorSpace);
    }

    @Override // org.webrtc.mozi.VideoFrameDrawer
    public void release() {
        Logging.d("RTCVideoEglDrawer", "release");
        this.yuvUploader.release();
        this.lastI420Frame = null;
        this.lastDrawRecord = null;
    }

    public void redrawFrame(RendererCommon.GlDrawer drawer, float[] verticesCoord, boolean mirror, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        Logging.d("RTCVideoEglDrawer", "redrawFrame");
        DrawRecord drawRecord = this.lastDrawRecord;
        if (drawRecord != null) {
            drawRecord.redraw(drawer, verticesCoord, mirror, viewportX, viewportY, viewportWidth, viewportHeight);
        }
    }

    public void clearRedraw() {
        Logging.d("RTCVideoEglDrawer", "clearRedraw");
        DrawRecord drawRecord = this.lastDrawRecord;
        if (drawRecord != null) {
            drawRecord.setValid(false);
        }
    }

    public boolean canRedraw() {
        DrawRecord drawRecord = this.lastDrawRecord;
        return drawRecord != null && drawRecord.canRedraw();
    }
}
