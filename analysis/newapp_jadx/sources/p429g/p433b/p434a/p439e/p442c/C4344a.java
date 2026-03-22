package p429g.p433b.p434a.p439e.p442c;

import java.util.concurrent.atomic.AtomicReference;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p429g.p433b.p434a.p435a.InterfaceC4335b;
import p429g.p433b.p434a.p436b.InterfaceC4336a;
import p429g.p433b.p434a.p437c.C4337a;
import p429g.p433b.p434a.p437c.C4339c;
import p429g.p433b.p434a.p438d.InterfaceC4341a;
import p429g.p433b.p434a.p439e.p440a.EnumC4342a;
import p429g.p433b.p434a.p444f.C4346a;

/* renamed from: g.b.a.e.c.a */
/* loaded from: classes2.dex */
public final class C4344a<T> extends AtomicReference<InterfaceC4336a> implements InterfaceC4335b<T>, InterfaceC4336a {
    private static final long serialVersionUID = -7012088219455310787L;

    /* renamed from: c */
    public final InterfaceC4341a<? super T> f11197c;

    /* renamed from: e */
    public final InterfaceC4341a<? super Throwable> f11198e;

    public C4344a(InterfaceC4341a<? super T> interfaceC4341a, InterfaceC4341a<? super Throwable> interfaceC4341a2) {
        this.f11197c = interfaceC4341a;
        this.f11198e = interfaceC4341a2;
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    /* renamed from: a */
    public void mo4910a(InterfaceC4336a interfaceC4336a) {
        if (compareAndSet(null, interfaceC4336a)) {
            return;
        }
        ((C4346a.a) interfaceC4336a).m4916a();
        if (get() != EnumC4342a.DISPOSED) {
            C2354n.m2481h1(new C4339c("Disposable already set!"));
        }
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    public void onError(Throwable th) {
        lazySet(EnumC4342a.DISPOSED);
        try {
            this.f11198e.accept(th);
        } catch (Throwable th2) {
            C2354n.m2430S1(th2);
            C2354n.m2481h1(new C4337a(th, th2));
        }
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    public void onSuccess(T t) {
        lazySet(EnumC4342a.DISPOSED);
        try {
            this.f11197c.accept(t);
        } catch (Throwable th) {
            C2354n.m2430S1(th);
            C2354n.m2481h1(th);
        }
    }
}
