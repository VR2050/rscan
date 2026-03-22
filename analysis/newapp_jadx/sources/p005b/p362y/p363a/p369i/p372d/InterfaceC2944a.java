package p005b.p362y.p363a.p369i.p372d;

import android.graphics.Bitmap;
import android.view.View;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import java.io.File;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p366f.InterfaceC2929e;
import p005b.p362y.p363a.p369i.p371c.AbstractC2942b;

/* renamed from: b.y.a.i.d.a */
/* loaded from: classes2.dex */
public interface InterfaceC2944a {
    /* renamed from: a */
    Bitmap mo3408a();

    /* renamed from: b */
    void mo3409b(InterfaceC2928d interfaceC2928d, boolean z);

    /* renamed from: c */
    void mo3410c();

    /* renamed from: d */
    void mo3411d(File file, boolean z, InterfaceC2929e interfaceC2929e);

    View getRenderView();

    void setGLEffectFilter(GSYVideoGLView.InterfaceC4091c interfaceC4091c);

    void setGLMVPMatrix(float[] fArr);

    void setGLRenderer(AbstractC2942b abstractC2942b);

    void setRenderMode(int i2);
}
