package p429g.p433b.p434a.p435a;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p429g.p433b.p434a.p436b.InterfaceC4336a;
import p429g.p433b.p434a.p438d.InterfaceC4341a;
import p429g.p433b.p434a.p439e.p441b.C4343a;
import p429g.p433b.p434a.p439e.p442c.C4344a;

/* renamed from: g.b.a.a.a */
/* loaded from: classes2.dex */
public abstract class AbstractC4334a<T> {
    /* renamed from: b */
    public final InterfaceC4336a m4908b(InterfaceC4341a<? super T> interfaceC4341a) {
        C4344a c4344a = new C4344a(interfaceC4341a, C4343a.f11196a);
        try {
            mo4909c(c4344a);
            return c4344a;
        } catch (NullPointerException e2) {
            throw e2;
        } catch (Throwable th) {
            C2354n.m2430S1(th);
            NullPointerException nullPointerException = new NullPointerException("subscribeActual failed");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    /* renamed from: c */
    public abstract void mo4909c(InterfaceC4335b<? super T> interfaceC4335b);
}
