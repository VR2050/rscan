package p476m.p496b.p500b.p504i;

import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4929d;

/* renamed from: m.b.b.i.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4947a<T> {

    /* renamed from: a */
    public final AbstractC4926a<T, ?> f12621a;

    /* renamed from: b */
    public final C4929d<T> f12622b;

    /* renamed from: c */
    public final String f12623c;

    /* renamed from: d */
    public final String[] f12624d;

    /* renamed from: e */
    public final Thread f12625e = Thread.currentThread();

    public AbstractC4947a(AbstractC4926a<T, ?> abstractC4926a, String str, String[] strArr) {
        this.f12621a = abstractC4926a;
        this.f12622b = new C4929d<>(abstractC4926a);
        this.f12623c = str;
        this.f12624d = strArr;
    }
}
