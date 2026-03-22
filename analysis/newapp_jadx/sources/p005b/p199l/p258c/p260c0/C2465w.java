package p005b.p199l.p258c.p260c0;

import java.lang.reflect.Method;

/* renamed from: b.l.c.c0.w */
/* loaded from: classes2.dex */
public final class C2465w extends AbstractC2468z {

    /* renamed from: a */
    public final /* synthetic */ Method f6636a;

    /* renamed from: b */
    public final /* synthetic */ int f6637b;

    public C2465w(Method method, int i2) {
        this.f6636a = method;
        this.f6637b = i2;
    }

    @Override // p005b.p199l.p258c.p260c0.AbstractC2468z
    /* renamed from: b */
    public <T> T mo2824b(Class<T> cls) {
        AbstractC2468z.m2825a(cls);
        return (T) this.f6636a.invoke(null, cls, Integer.valueOf(this.f6637b));
    }
}
