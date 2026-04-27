package org.webrtc.mozi;

import android.graphics.Matrix;
import android.opengl.GLES20;
import java.nio.ByteBuffer;
import org.webrtc.mozi.GlGenericDrawer;
import org.webrtc.mozi.ThreadUtils;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class YuvConverter {
    private static final String FRAGMENT_SHADER = "uniform vec2 xUnit;\nuniform vec4 coeffs;\n\nvoid main() {\n  gl_FragColor.r = coeffs.a + dot(coeffs.rgb,\n      sample(tc - 1.5 * xUnit).rgb);\n  gl_FragColor.g = coeffs.a + dot(coeffs.rgb,\n      sample(tc - 0.5 * xUnit).rgb);\n  gl_FragColor.b = coeffs.a + dot(coeffs.rgb,\n      sample(tc + 0.5 * xUnit).rgb);\n  gl_FragColor.a = coeffs.a + dot(coeffs.rgb,\n      sample(tc + 1.5 * xUnit).rgb);\n}\n";
    private final ThreadUtils.ThreadChecker threadChecker = new ThreadUtils.ThreadChecker();
    private final GlTextureFrameBuffer i420TextureFrameBuffer = new GlTextureFrameBuffer(6408);
    private final ShaderCallbacks shaderCallbacks = new ShaderCallbacks();
    private final GlGenericDrawer drawer = new GlGenericDrawer(FRAGMENT_SHADER, this.shaderCallbacks);

    private static class ShaderCallbacks implements GlGenericDrawer.ShaderCallbacks {
        private float[] coeffs;
        private int coeffsLoc;
        private float stepSize;
        private int xUnitLoc;
        private static final float[] yCoeffs = {0.2987856f, 0.5871095f, 0.1141049f, 0.0f};
        private static final float[] uCoeffs = {-0.16880542f, -0.3317003f, 0.5005057f, 0.5f};
        private static final float[] vCoeffs = {0.4997964f, -0.4184672f, -0.0813292f, 0.5f};

        private ShaderCallbacks() {
        }

        public void setPlaneY() {
            this.coeffs = yCoeffs;
            this.stepSize = 1.0f;
        }

        public void setPlaneU() {
            this.coeffs = uCoeffs;
            this.stepSize = 2.0f;
        }

        public void setPlaneV() {
            this.coeffs = vCoeffs;
            this.stepSize = 2.0f;
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onNewShader(GlShader shader) {
            this.xUnitLoc = shader.getUniformLocation("xUnit");
            this.coeffsLoc = shader.getUniformLocation("coeffs");
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onPrepareShader(GlShader shader, float[] texMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight) {
            GLES20.glUniform4fv(this.coeffsLoc, 1, this.coeffs, 0);
            int i = this.xUnitLoc;
            float f = this.stepSize;
            GLES20.glUniform2f(i, (texMatrix[0] * f) / frameWidth, (f * texMatrix[1]) / frameWidth);
        }
    }

    public YuvConverter() {
        this.threadChecker.detachThread();
    }

    public VideoFrame.I420Buffer convert(VideoFrame.TextureBuffer inputTextureBuffer) {
        this.threadChecker.checkIsOnValidThread();
        int frameWidth = inputTextureBuffer.getWidth();
        int frameHeight = inputTextureBuffer.getHeight();
        int stride = ((frameWidth + 7) / 8) * 8;
        int uvHeight = (frameHeight + 1) / 2;
        int totalHeight = frameHeight + uvHeight;
        ByteBuffer i420ByteBuffer = JniCommon.nativeAllocateByteBuffer(stride * totalHeight);
        int viewportWidth = stride / 4;
        Matrix renderMatrix = new Matrix();
        renderMatrix.preTranslate(0.5f, 0.5f);
        renderMatrix.preScale(1.0f, -1.0f);
        renderMatrix.preTranslate(-0.5f, -0.5f);
        this.i420TextureFrameBuffer.setSize(viewportWidth, totalHeight);
        GLES20.glBindFramebuffer(36160, this.i420TextureFrameBuffer.getFrameBufferId());
        GlUtil.checkNoGLES2Error("glBindFramebuffer");
        this.shaderCallbacks.setPlaneY();
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, frameWidth, frameHeight, 0, 0, viewportWidth, frameHeight);
        this.shaderCallbacks.setPlaneU();
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, frameWidth, frameHeight, 0, frameHeight, viewportWidth / 2, uvHeight);
        this.shaderCallbacks.setPlaneV();
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, frameWidth, frameHeight, viewportWidth / 2, frameHeight, viewportWidth / 2, uvHeight);
        GLES20.glReadPixels(0, 0, this.i420TextureFrameBuffer.getWidth(), this.i420TextureFrameBuffer.getHeight(), 6408, 5121, i420ByteBuffer);
        GlUtil.checkNoGLES2Error("YuvConverter.convert");
        GLES20.glBindFramebuffer(36160, 0);
        int uPos = (stride * frameHeight) + 0;
        int vPos = uPos + (stride / 2);
        i420ByteBuffer.position(0);
        i420ByteBuffer.limit((stride * frameHeight) + 0);
        ByteBuffer dataY = i420ByteBuffer.slice();
        i420ByteBuffer.position(uPos);
        int uvSize = ((uvHeight - 1) * stride) + (stride / 2);
        i420ByteBuffer.limit(uPos + uvSize);
        ByteBuffer dataU = i420ByteBuffer.slice();
        i420ByteBuffer.position(vPos);
        i420ByteBuffer.limit(vPos + uvSize);
        ByteBuffer dataV = i420ByteBuffer.slice();
        return JavaI420Buffer.wrap(frameWidth, frameHeight, dataY, stride, dataU, stride, dataV, stride, YuvConverter$$Lambda$1.lambdaFactory$(i420ByteBuffer));
    }

    public VideoFrame.I420Buffer convertByRotation(VideoFrame.TextureBuffer inputTextureBuffer, int rotation) {
        this.threadChecker.checkIsOnValidThread();
        int frameWidth = (rotation == 0 || rotation == 180) ? inputTextureBuffer.getWidth() : inputTextureBuffer.getHeight();
        int frameHeight = (rotation == 0 || rotation == 180) ? inputTextureBuffer.getHeight() : inputTextureBuffer.getWidth();
        int stride = ((frameWidth + 7) / 8) * 8;
        int uvHeight = (frameHeight + 1) / 2;
        int totalHeight = frameHeight + uvHeight;
        ByteBuffer i420ByteBuffer = JniCommon.nativeAllocateByteBuffer(stride * totalHeight);
        int viewportWidth = stride / 4;
        Matrix renderMatrix = new Matrix();
        renderMatrix.preTranslate(0.5f, 0.5f);
        renderMatrix.preScale(1.0f, -1.0f);
        renderMatrix.preRotate(rotation);
        renderMatrix.preTranslate(-0.5f, -0.5f);
        this.i420TextureFrameBuffer.setSize(viewportWidth, totalHeight);
        GLES20.glBindFramebuffer(36160, this.i420TextureFrameBuffer.getFrameBufferId());
        GlUtil.checkNoGLES2Error("glBindFramebuffer");
        this.shaderCallbacks.setPlaneY();
        int i = frameWidth;
        int i2 = frameHeight;
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, i, i2, 0, 0, viewportWidth, frameHeight);
        this.shaderCallbacks.setPlaneU();
        int i3 = frameHeight;
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, i, i2, 0, i3, viewportWidth / 2, uvHeight);
        this.shaderCallbacks.setPlaneV();
        VideoFrameDrawer.drawTexture(this.drawer, inputTextureBuffer, renderMatrix, i, i2, viewportWidth / 2, i3, viewportWidth / 2, uvHeight);
        GLES20.glReadPixels(0, 0, this.i420TextureFrameBuffer.getWidth(), this.i420TextureFrameBuffer.getHeight(), 6408, 5121, i420ByteBuffer);
        GlUtil.checkNoGLES2Error("YuvConverter.convert");
        GLES20.glBindFramebuffer(36160, 0);
        int uPos = (stride * frameHeight) + 0;
        int vPos = uPos + (stride / 2);
        i420ByteBuffer.position(0);
        i420ByteBuffer.limit((stride * frameHeight) + 0);
        ByteBuffer dataY = i420ByteBuffer.slice();
        i420ByteBuffer.position(uPos);
        int uvSize = ((uvHeight - 1) * stride) + (stride / 2);
        i420ByteBuffer.limit(uPos + uvSize);
        ByteBuffer dataU = i420ByteBuffer.slice();
        i420ByteBuffer.position(vPos);
        i420ByteBuffer.limit(vPos + uvSize);
        ByteBuffer dataV = i420ByteBuffer.slice();
        return JavaI420Buffer.wrap(frameWidth, frameHeight, dataY, stride, dataU, stride, dataV, stride, YuvConverter$$Lambda$2.lambdaFactory$(i420ByteBuffer));
    }

    public void release() {
        this.threadChecker.checkIsOnValidThread();
        this.drawer.release();
        this.i420TextureFrameBuffer.release();
        this.threadChecker.detachThread();
    }
}
