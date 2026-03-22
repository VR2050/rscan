package p379c.p380a.p382a2;

import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3072k;
import p379c.p380a.p381a.C2961j;
import p379c.p380a.p381a.C2970s;

/* renamed from: c.a.a2.h */
/* loaded from: classes2.dex */
public final class C2985h<E> extends AbstractC2997t implements InterfaceC2995r<E> {

    /* renamed from: g */
    @JvmField
    @Nullable
    public final Throwable f8181g;

    public C2985h(@Nullable Throwable th) {
        this.f8181g = th;
    }

    @Override // p379c.p380a.p382a2.InterfaceC2995r
    /* renamed from: a */
    public Object mo3492a() {
        return this;
    }

    @Override // p379c.p380a.p382a2.InterfaceC2995r
    /* renamed from: e */
    public void mo3470e(E e2) {
    }

    @Override // p379c.p380a.p382a2.InterfaceC2995r
    @Nullable
    /* renamed from: f */
    public C2970s mo3471f(E e2, @Nullable C2961j.b bVar) {
        return C3072k.f8424a;
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: r */
    public void mo3487r() {
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: s */
    public Object mo3488s() {
        return this;
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: t */
    public void mo3489t(@NotNull C2985h<?> c2985h) {
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Closed@");
        m586H.append(C2354n.m2495m0(this));
        m586H.append('[');
        m586H.append(this.f8181g);
        m586H.append(']');
        return m586H.toString();
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    @Nullable
    /* renamed from: u */
    public C2970s mo3490u(@Nullable C2961j.b bVar) {
        return C3072k.f8424a;
    }

    @NotNull
    /* renamed from: w */
    public final Throwable m3493w() {
        Throwable th = this.f8181g;
        return th != null ? th : new C2986i("Channel was closed");
    }

    @NotNull
    /* renamed from: x */
    public final Throwable m3494x() {
        Throwable th = this.f8181g;
        return th != null ? th : new C2987j("Channel was closed");
    }
}
