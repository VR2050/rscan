package org.webrtc.mozi;

import android.graphics.Matrix;
import android.opengl.GLES20;
import java.nio.FloatBuffer;
import org.webrtc.mozi.GlGenericDrawer;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class TextureAlignmentDrawer {
    private static final String FRAGMENT_SHADER_STRING = "void main() {\n  gl_FragColor = sample(tc);\n}\n";
    private final GlTextureFrameBuffer texture = new GlTextureFrameBuffer(6408);
    private final ShaderCallbacks callback = new ShaderCallbacks();
    private final GlGenericDrawer drawer = new GlGenericDrawer(FRAGMENT_SHADER_STRING, this.callback);
    private McsConfigHelper configHelper = null;

    private static class ShaderCallbacks implements GlGenericDrawer.ShaderCallbacks {
        private float xOffset;

        private ShaderCallbacks() {
        }

        public void setXOffset(float offset) {
            this.xOffset = offset;
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onNewShader(GlShader shader) {
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onPrepareShader(GlShader shader, float[] texMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight) {
            float f = this.xOffset;
            FloatBuffer vertex_coords = GlUtil.createFloatBuffer(new float[]{-1.0f, -1.0f, 1.0f - f, -1.0f, -1.0f, 1.0f, 1.0f - f, 1.0f});
            shader.setVertexAttribArray("in_pos", 2, vertex_coords);
        }
    }

    public void alignDraw(VideoFrame.TextureBuffer textureBuffer, int alignment) {
        int frameWidth = textureBuffer.getWidth();
        int frameHeight = textureBuffer.getHeight();
        int newWidth = ((alignment - 1) + frameWidth) & (~(alignment - 1));
        Matrix matrix = new Matrix();
        this.texture.setSize(newWidth, frameHeight);
        GLES20.glBindFramebuffer(36160, this.texture.getFrameBufferId());
        GlUtil.checkNoGLES2Error("glBindFramebuffer");
        float xOffset = ((newWidth - frameWidth) * 2.0f) / newWidth;
        this.callback.setXOffset(xOffset);
        VideoFrameDrawer.drawTexture(this.drawer, textureBuffer, matrix, newWidth, frameHeight, 0, 0, newWidth, frameHeight);
        GlUtil.checkNoGLES2Error("TextureAlignmentDrawer.alignDraw");
        GLES20.glBindFramebuffer(36160, 0);
        McsConfigHelper mcsConfigHelper = this.configHelper;
        if (mcsConfigHelper != null && mcsConfigHelper.getVideoCodecConfig().isFixAlignDrawerBlack()) {
            GLES20.glFinish();
        }
    }

    public void setConfigHelper(McsConfigHelper helper) {
        this.configHelper = helper;
    }

    public int getTextureWidth() {
        return this.texture.getWidth();
    }

    public int getTextureHeight() {
        return this.texture.getHeight();
    }

    public int getTextureId() {
        return this.texture.getTextureId();
    }

    public void release() {
        this.drawer.release();
        this.texture.release();
    }
}
