package p005b.p362y.p363a.p369i.p371c;

import android.view.Surface;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2945a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c;

/* renamed from: b.y.a.i.c.a */
/* loaded from: classes2.dex */
public class RunnableC2941a implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ Surface f8047c;

    /* renamed from: e */
    public final /* synthetic */ AbstractC2942b f8048e;

    public RunnableC2941a(AbstractC2942b abstractC2942b, Surface surface) {
        this.f8048e = abstractC2942b;
        this.f8047c = surface;
    }

    @Override // java.lang.Runnable
    public void run() {
        InterfaceC2945a interfaceC2945a = this.f8048e.f8050e;
        if (interfaceC2945a != null) {
            Surface surface = this.f8047c;
            InterfaceC2947c interfaceC2947c = ((GSYVideoGLView) interfaceC2945a).f10778i;
            if (interfaceC2947c != null) {
                interfaceC2947c.onSurfaceAvailable(surface);
            }
        }
    }
}
