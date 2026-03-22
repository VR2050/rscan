package p005b.p199l.p258c.p260c0;

import java.lang.reflect.Method;

/* renamed from: b.l.c.c0.v */
/* loaded from: classes2.dex */
public final class C2464v extends AbstractC2468z {

    /* renamed from: a */
    public final /* synthetic */ Method f6634a;

    /* renamed from: b */
    public final /* synthetic */ Object f6635b;

    public C2464v(Method method, Object obj) {
        this.f6634a = method;
        this.f6635b = obj;
    }

    @Override // p005b.p199l.p258c.p260c0.AbstractC2468z
    /* renamed from: b */
    public <T> T mo2824b(Class<T> cls) {
        AbstractC2468z.m2825a(cls);
        return (T) this.f6634a.invoke(this.f6635b, cls);
    }
}
