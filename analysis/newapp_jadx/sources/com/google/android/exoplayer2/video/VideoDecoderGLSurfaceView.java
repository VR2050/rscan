package com.google.android.exoplayer2.video;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.util.AttributeSet;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p251q1.C2381m;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2380l;

/* loaded from: classes.dex */
public class VideoDecoderGLSurfaceView extends GLSurfaceView {

    /* renamed from: c */
    public final C2381m f9758c;

    public VideoDecoderGLSurfaceView(Context context) {
        this(context, null);
    }

    public InterfaceC2380l getVideoDecoderOutputBufferRenderer() {
        return this.f9758c;
    }

    public VideoDecoderGLSurfaceView(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        C2381m c2381m = new C2381m(this);
        this.f9758c = c2381m;
        setPreserveEGLContextOnPause(true);
        setEGLContextClientVersion(2);
        setRenderer(c2381m);
        setRenderMode(0);
    }
}
