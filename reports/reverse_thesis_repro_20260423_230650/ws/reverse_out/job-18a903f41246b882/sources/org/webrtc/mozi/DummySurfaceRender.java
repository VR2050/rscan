package org.webrtc.mozi;

import android.graphics.Matrix;
import android.opengl.GLES20;
import android.os.Handler;
import android.os.HandlerThread;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.ImageReaderCore;

/* JADX INFO: loaded from: classes3.dex */
public class DummySurfaceRender {
    private GlRectDrawer drawer;
    private EglBase eglBase;
    private final String TAG = "DummySurfaceRender";
    private ImageReaderCore iReader = null;
    private final Matrix renderMatrix = new Matrix();

    private void executeGL(Runnable r) {
        AThreadPool.executeGL(r);
    }

    public void init(final EglBase.Context sharedContext) {
        executeGL(new Runnable() { // from class: org.webrtc.mozi.DummySurfaceRender.1
            @Override // java.lang.Runnable
            public void run() {
                DummySurfaceRender.this.eglBase = EglBase.create(sharedContext, EglBase.CONFIG_RECORDABLE);
                DummySurfaceRender.this.drawer = new GlRectDrawer();
            }
        });
    }

    public int drawTexture(final int width, final int height, final int oesTextureId, final boolean oes, final float[] transformationMatrix, ImageReaderCore.OnImageReaderCoreListener listener) {
        if (this.iReader == null) {
            HandlerThread thread = new HandlerThread("handler");
            thread.start();
            Handler handler = new Handler(thread.getLooper());
            ImageReaderCore imageReaderCore = new ImageReaderCore(width, height, null, handler);
            this.iReader = imageReaderCore;
            this.eglBase.createSurface(imageReaderCore.getInputSurface());
        }
        this.iReader.setImageReaderCoreListener(listener);
        executeGL(new Runnable() { // from class: org.webrtc.mozi.DummySurfaceRender.2
            @Override // java.lang.Runnable
            public void run() {
                DummySurfaceRender.this.eglBase.makeCurrent();
                GLES20.glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
                GLES20.glClear(16384);
                boolean textureGoRgb = !oes;
                if (textureGoRgb) {
                    GlRectDrawer glRectDrawer = DummySurfaceRender.this.drawer;
                    int i = oesTextureId;
                    float[] fArr = transformationMatrix;
                    int i2 = width;
                    int i3 = height;
                    glRectDrawer.drawRgb(i, fArr, i2, i3, 0, 0, i2, i3);
                } else {
                    GlRectDrawer glRectDrawer2 = DummySurfaceRender.this.drawer;
                    int i4 = oesTextureId;
                    float[] fArr2 = transformationMatrix;
                    int i5 = width;
                    int i6 = height;
                    glRectDrawer2.drawOes(i4, fArr2, i5, i6, 0, 0, i5, i6);
                }
                DummySurfaceRender.this.eglBase.swapBuffers();
            }
        });
        return 0;
    }

    public void release() {
        executeGL(new Runnable() { // from class: org.webrtc.mozi.DummySurfaceRender.3
            @Override // java.lang.Runnable
            public void run() {
                if (DummySurfaceRender.this.iReader != null) {
                    DummySurfaceRender.this.iReader.release();
                    DummySurfaceRender.this.iReader = null;
                }
                if (DummySurfaceRender.this.drawer != null) {
                    DummySurfaceRender.this.drawer.release();
                    DummySurfaceRender.this.drawer = null;
                }
                if (DummySurfaceRender.this.eglBase != null) {
                    DummySurfaceRender.this.eglBase.release();
                    DummySurfaceRender.this.eglBase = null;
                }
            }
        });
    }
}
