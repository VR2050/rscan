package org.webrtc.mozi;

import android.opengl.GLES20;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.RendererCommon;

/* JADX INFO: loaded from: classes3.dex */
class GlGenericDrawer implements RendererCommon.GlDrawer {
    private static final String DEFAULT_VERTEX_SHADER_STRING = "varying vec2 tc;\nattribute vec4 in_pos;\nattribute vec4 in_tc;\nuniform mat4 tex_mat;\nvoid main() {\n  gl_Position = in_pos;\n  tc = (tex_mat * in_tc).xy;\n}\n";
    private static final FloatBuffer FULL_RECTANGLE_BUFFER = GlUtil.createFloatBuffer(new float[]{-1.0f, -1.0f, 1.0f, -1.0f, -1.0f, 1.0f, 1.0f, 1.0f});
    private static final FloatBuffer FULL_RECTANGLE_TEXTURE_BUFFER = GlUtil.createFloatBuffer(new float[]{0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f});
    private static final String INPUT_TEXTURE_COORDINATE_NAME = "in_tc";
    private static final String INPUT_VERTEX_COORDINATE_NAME = "in_pos";
    private static final String TEXTURE_MATRIX_NAME = "tex_mat";

    @Nullable
    private GlShader currentShader;

    @Nullable
    private ShaderType currentShaderType;
    private final String genericFragmentSource;
    private int inPosLocation;
    private int inTcLocation;
    private final ShaderCallbacks shaderCallbacks;
    private int texMatrixLocation;
    private final String vertexShader;

    public interface ShaderCallbacks {
        void onNewShader(GlShader glShader);

        void onPrepareShader(GlShader glShader, float[] fArr, int i, int i2, int i3, int i4);
    }

    public enum ShaderType {
        OES,
        RGB,
        YUV
    }

    static String createFragmentShaderString(String genericFragmentSource, ShaderType shaderType, int colorSpace) {
        StringBuilder stringBuilder = new StringBuilder();
        if (shaderType == ShaderType.OES) {
            stringBuilder.append("#extension GL_OES_EGL_image_external : require\n");
        }
        stringBuilder.append("precision mediump float;\n");
        stringBuilder.append("varying vec2 tc;\n");
        Logging.d("GLGenericDrawer", "createFragmentShaderString: " + shaderType + " " + colorSpace);
        if (shaderType == ShaderType.YUV) {
            boolean fullrange = (colorSpace & 255) == 2;
            stringBuilder.append("uniform sampler2D y_tex;\n");
            stringBuilder.append("uniform sampler2D u_tex;\n");
            stringBuilder.append("uniform sampler2D v_tex;\n");
            stringBuilder.append("vec4 sample(vec2 p) {\n");
            if (fullrange) {
                stringBuilder.append("  float y = texture2D(y_tex, p).r;\n");
            } else {
                stringBuilder.append("  float y = texture2D(y_tex, p).r - 0.0625;\n");
            }
            stringBuilder.append("  float u = texture2D(u_tex, p).r - 0.5;\n");
            stringBuilder.append("  float v = texture2D(v_tex, p).r - 0.5;\n");
            if (fullrange) {
                stringBuilder.append("  return vec4(y + 1.403 * v, y - 0.344 * u - 0.714 * v, y + 1.77 * u, 1);\n");
            } else {
                stringBuilder.append("  return vec4(1.164 * y + 1.596 * v, 1.164 * y - 0.392 * u - 0.813 * v, 1.164 * y + 2.017 * u, 1);\n");
            }
            stringBuilder.append("}\n");
            stringBuilder.append(genericFragmentSource);
        } else {
            String samplerName = shaderType == ShaderType.OES ? "samplerExternalOES" : "sampler2D";
            stringBuilder.append("uniform ");
            stringBuilder.append(samplerName);
            stringBuilder.append(" tex;\n");
            stringBuilder.append(genericFragmentSource.replace("sample(", "texture2D(tex, "));
        }
        String samplerName2 = stringBuilder.toString();
        return samplerName2;
    }

    public GlGenericDrawer(String genericFragmentSource, ShaderCallbacks shaderCallbacks) {
        this(DEFAULT_VERTEX_SHADER_STRING, genericFragmentSource, shaderCallbacks);
    }

    public GlGenericDrawer(String vertexShader, String genericFragmentSource, ShaderCallbacks shaderCallbacks) {
        this.vertexShader = vertexShader;
        this.genericFragmentSource = genericFragmentSource;
        this.shaderCallbacks = shaderCallbacks;
    }

    GlShader createShader(ShaderType shaderType, int colorSpace) {
        return new GlShader(this.vertexShader, createFragmentShaderString(this.genericFragmentSource, shaderType, colorSpace));
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawOes(int oesTextureId, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        prepareShader(ShaderType.OES, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, 0);
        GLES20.glActiveTexture(33984);
        GLES20.glBindTexture(36197, oesTextureId);
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        GLES20.glBindTexture(36197, 0);
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawRgb(int textureId, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        prepareShader(ShaderType.RGB, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, 0);
        GLES20.glActiveTexture(33984);
        GLES20.glBindTexture(3553, textureId);
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        GLES20.glBindTexture(3553, 0);
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawYuv(int[] yuvTextures, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        prepareShader(ShaderType.YUV, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, 2);
        for (int i = 0; i < 3; i++) {
            GLES20.glActiveTexture(33984 + i);
            GLES20.glBindTexture(3553, yuvTextures[i]);
        }
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        for (int i2 = 0; i2 < 3; i2++) {
            GLES20.glActiveTexture(i2 + 33984);
            GLES20.glBindTexture(3553, 0);
        }
    }

    private void prepareShader(ShaderType shaderType, float[] texMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight, int colorSpace) {
        GlShader shader;
        if (shaderType.equals(this.currentShaderType)) {
            shader = this.currentShader;
        } else {
            this.currentShaderType = shaderType;
            GlShader glShader = this.currentShader;
            if (glShader != null) {
                glShader.release();
            }
            shader = createShader(shaderType, colorSpace);
            this.currentShader = shader;
            shader.useProgram();
            if (shaderType == ShaderType.YUV) {
                GLES20.glUniform1i(shader.getUniformLocation("y_tex"), 0);
                GLES20.glUniform1i(shader.getUniformLocation("u_tex"), 1);
                GLES20.glUniform1i(shader.getUniformLocation("v_tex"), 2);
            } else {
                GLES20.glUniform1i(shader.getUniformLocation("tex"), 0);
            }
            GlUtil.checkNoGLES2Error("Create shader");
            this.shaderCallbacks.onNewShader(shader);
            this.texMatrixLocation = shader.getUniformLocation(TEXTURE_MATRIX_NAME);
            this.inPosLocation = shader.getAttribLocation(INPUT_VERTEX_COORDINATE_NAME);
            this.inTcLocation = shader.getAttribLocation(INPUT_TEXTURE_COORDINATE_NAME);
        }
        shader.useProgram();
        GLES20.glEnableVertexAttribArray(this.inPosLocation);
        GLES20.glVertexAttribPointer(this.inPosLocation, 2, 5126, false, 0, (Buffer) FULL_RECTANGLE_BUFFER);
        GLES20.glEnableVertexAttribArray(this.inTcLocation);
        GLES20.glVertexAttribPointer(this.inTcLocation, 2, 5126, false, 0, (Buffer) FULL_RECTANGLE_TEXTURE_BUFFER);
        GLES20.glUniformMatrix4fv(this.texMatrixLocation, 1, false, texMatrix, 0);
        this.shaderCallbacks.onPrepareShader(shader, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight);
        GlUtil.checkNoGLES2Error("Prepare shader");
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawOes2(int oesTextureId, float[] verticesCoord, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        prepareShader2(ShaderType.OES, verticesCoord, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, 0);
        GLES20.glActiveTexture(33984);
        GLES20.glBindTexture(36197, oesTextureId);
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        GLES20.glBindTexture(36197, 0);
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawRgb2(int textureId, float[] verticesCoord, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight) {
        prepareShader2(ShaderType.RGB, verticesCoord, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, 0);
        GLES20.glActiveTexture(33984);
        GLES20.glBindTexture(3553, textureId);
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        GLES20.glBindTexture(3553, 0);
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void drawYuv2(int[] yuvTextures, float[] verticesCoord, float[] texMatrix, int frameWidth, int frameHeight, int viewportX, int viewportY, int viewportWidth, int viewportHeight, int colorSpace) {
        prepareShader2(ShaderType.YUV, verticesCoord, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight, colorSpace);
        for (int i = 0; i < 3; i++) {
            GLES20.glActiveTexture(33984 + i);
            GLES20.glBindTexture(3553, yuvTextures[i]);
        }
        GLES20.glViewport(viewportX, viewportY, viewportWidth, viewportHeight);
        GLES20.glDrawArrays(5, 0, 4);
        for (int i2 = 0; i2 < 3; i2++) {
            GLES20.glActiveTexture(i2 + 33984);
            GLES20.glBindTexture(3553, 0);
        }
    }

    private void prepareShader2(ShaderType shaderType, float[] verticesCoord, float[] texMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight, int colorSpace) {
        GlShader shader;
        if (shaderType.equals(this.currentShaderType)) {
            shader = this.currentShader;
        } else {
            this.currentShaderType = shaderType;
            GlShader glShader = this.currentShader;
            if (glShader != null) {
                glShader.release();
            }
            shader = createShader(shaderType, colorSpace);
            this.currentShader = shader;
            Logging.i("GlGenericDrawer", "prepareShader2 type:" + shaderType + ", " + shader.getProgram());
            shader.useProgram();
            if (shaderType == ShaderType.YUV) {
                GLES20.glUniform1i(shader.getUniformLocation("y_tex"), 0);
                GLES20.glUniform1i(shader.getUniformLocation("u_tex"), 1);
                GLES20.glUniform1i(shader.getUniformLocation("v_tex"), 2);
            } else {
                GLES20.glUniform1i(shader.getUniformLocation("tex"), 0);
            }
            GlUtil.checkNoGLES2Error("Create shader");
            this.shaderCallbacks.onNewShader(shader);
            this.texMatrixLocation = shader.getUniformLocation(TEXTURE_MATRIX_NAME);
            this.inPosLocation = shader.getAttribLocation(INPUT_VERTEX_COORDINATE_NAME);
            this.inTcLocation = shader.getAttribLocation(INPUT_TEXTURE_COORDINATE_NAME);
        }
        shader.useProgram();
        FloatBuffer verticesCoordBuffer = GlUtil.createFloatBuffer(verticesCoord);
        GLES20.glEnableVertexAttribArray(this.inPosLocation);
        GLES20.glVertexAttribPointer(this.inPosLocation, 2, 5126, false, 0, (Buffer) verticesCoordBuffer);
        GLES20.glEnableVertexAttribArray(this.inTcLocation);
        GLES20.glVertexAttribPointer(this.inTcLocation, 2, 5126, false, 0, (Buffer) FULL_RECTANGLE_TEXTURE_BUFFER);
        GLES20.glUniformMatrix4fv(this.texMatrixLocation, 1, false, texMatrix, 0);
        this.shaderCallbacks.onPrepareShader(shader, texMatrix, frameWidth, frameHeight, viewportWidth, viewportHeight);
        GlUtil.checkNoGLES2Error("Prepare shader");
    }

    @Override // org.webrtc.mozi.RendererCommon.GlDrawer
    public void release() {
        if (this.currentShader != null) {
            Logging.i("GlGenericDrawer", "release");
            this.currentShader.release();
            this.currentShader = null;
            this.currentShaderType = null;
        }
    }
}
