package p005b.p199l.p200a.p201a.p251q1;

import android.view.Surface;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;

/* renamed from: b.l.a.a.q1.e */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC2373e implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC2386r.a f6169c;

    /* renamed from: e */
    public final /* synthetic */ Surface f6170e;

    public /* synthetic */ RunnableC2373e(InterfaceC2386r.a aVar, Surface surface) {
        this.f6169c = aVar;
        this.f6170e = surface;
    }

    @Override // java.lang.Runnable
    public final void run() {
        InterfaceC2386r.a aVar = this.f6169c;
        Surface surface = this.f6170e;
        InterfaceC2386r interfaceC2386r = aVar.f6269b;
        int i2 = C2344d0.f6035a;
        interfaceC2386r.onRenderedFirstFrame(surface);
    }
}
