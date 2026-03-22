package p005b.p199l.p258c.p260c0;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import p005b.p131d.p132a.p133a.C1499a;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: b.l.c.c0.h */
/* loaded from: classes2.dex */
public class C2450h<T> implements InterfaceC2462t<T> {

    /* renamed from: a */
    public final /* synthetic */ Constructor f6596a;

    public C2450h(C2449g c2449g, Constructor constructor) {
        this.f6596a = constructor;
    }

    @Override // p005b.p199l.p258c.p260c0.InterfaceC2462t
    /* renamed from: a */
    public T mo2810a() {
        try {
            return (T) this.f6596a.newInstance(null);
        } catch (IllegalAccessException e2) {
            throw new AssertionError(e2);
        } catch (InstantiationException e3) {
            StringBuilder m586H = C1499a.m586H("Failed to invoke ");
            m586H.append(this.f6596a);
            m586H.append(" with no args");
            throw new RuntimeException(m586H.toString(), e3);
        } catch (InvocationTargetException e4) {
            StringBuilder m586H2 = C1499a.m586H("Failed to invoke ");
            m586H2.append(this.f6596a);
            m586H2.append(" with no args");
            throw new RuntimeException(m586H2.toString(), e4.getTargetException());
        }
    }
}
