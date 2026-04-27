package org.webrtc.mozi;

import org.webrtc.mozi.GlGenericDrawer;

/* JADX INFO: loaded from: classes3.dex */
public class GlRectDrawer extends GlGenericDrawer {
    private static final String FRAGMENT_SHADER = "void main() {\n  gl_FragColor = sample(tc);\n}\n";

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawOes(int i, float[] fArr, int i2, int i3, int i4, int i5, int i6, int i7) {
        super.drawOes(i, fArr, i2, i3, i4, i5, i6, i7);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawOes2(int i, float[] fArr, float[] fArr2, int i2, int i3, int i4, int i5, int i6, int i7) {
        super.drawOes2(i, fArr, fArr2, i2, i3, i4, i5, i6, i7);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawRgb(int i, float[] fArr, int i2, int i3, int i4, int i5, int i6, int i7) {
        super.drawRgb(i, fArr, i2, i3, i4, i5, i6, i7);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawRgb2(int i, float[] fArr, float[] fArr2, int i2, int i3, int i4, int i5, int i6, int i7) {
        super.drawRgb2(i, fArr, fArr2, i2, i3, i4, i5, i6, i7);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawYuv(int[] iArr, float[] fArr, int i, int i2, int i3, int i4, int i5, int i6) {
        super.drawYuv(iArr, fArr, i, i2, i3, i4, i5, i6);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void drawYuv2(int[] iArr, float[] fArr, float[] fArr2, int i, int i2, int i3, int i4, int i5, int i6, int i7) {
        super.drawYuv2(iArr, fArr, fArr2, i, i2, i3, i4, i5, i6, i7);
    }

    @Override // org.webrtc.mozi.GlGenericDrawer, org.webrtc.mozi.RendererCommon.GlDrawer
    public /* bridge */ /* synthetic */ void release() {
        super.release();
    }

    private static class ShaderCallbacks implements GlGenericDrawer.ShaderCallbacks {
        private ShaderCallbacks() {
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onNewShader(GlShader shader) {
        }

        @Override // org.webrtc.mozi.GlGenericDrawer.ShaderCallbacks
        public void onPrepareShader(GlShader shader, float[] texMatrix, int frameWidth, int frameHeight, int viewportWidth, int viewportHeight) {
        }
    }

    public GlRectDrawer() {
        super(FRAGMENT_SHADER, new ShaderCallbacks());
    }
}
