package p379c.p380a.p382a2;

import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p381a.C2975x;

/* renamed from: c.a.a2.k */
/* loaded from: classes2.dex */
public class C2988k<E> extends AbstractC2978a<E> {

    /* renamed from: g */
    public final ReentrantLock f8182g;

    /* renamed from: h */
    public Object f8183h;

    public C2988k(@Nullable Function1<? super E, Unit> function1) {
        super(function1);
        this.f8182g = new ReentrantLock();
        this.f8183h = C2979b.f8158a;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    @NotNull
    /* renamed from: f */
    public String mo3476f() {
        StringBuilder m586H = C1499a.m586H("(value=");
        m586H.append(this.f8183h);
        m586H.append(')');
        return m586H.toString();
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: l */
    public final boolean mo3481l() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: o */
    public final boolean mo3483o() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    @NotNull
    /* renamed from: q */
    public Object mo3485q(E e2) {
        InterfaceC2995r<E> mo3461r;
        ReentrantLock reentrantLock = this.f8182g;
        reentrantLock.lock();
        try {
            C2985h<?> m3477g = m3477g();
            if (m3477g != null) {
                return m3477g;
            }
            if (this.f8183h == C2979b.f8158a) {
                do {
                    mo3461r = mo3461r();
                    if (mo3461r != null) {
                        if (mo3461r instanceof C2985h) {
                            Intrinsics.checkNotNull(mo3461r);
                            return mo3461r;
                        }
                        Intrinsics.checkNotNull(mo3461r);
                    }
                } while (mo3461r.mo3471f(e2, null) == null);
                Unit unit = Unit.INSTANCE;
                reentrantLock.unlock();
                Intrinsics.checkNotNull(mo3461r);
                mo3461r.mo3470e(e2);
                Intrinsics.checkNotNull(mo3461r);
                return mo3461r.mo3492a();
            }
            C2975x m3495z = m3495z(e2);
            if (m3495z == null) {
                return C2979b.f8159b;
            }
            throw m3495z;
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: t */
    public boolean mo3462t(@NotNull AbstractC2993p<? super E> abstractC2993p) {
        ReentrantLock reentrantLock = this.f8182g;
        reentrantLock.lock();
        try {
            return super.mo3462t(abstractC2993p);
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: u */
    public final boolean mo3463u() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: v */
    public final boolean mo3464v() {
        return this.f8183h == C2979b.f8158a;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: w */
    public void mo3465w(boolean z) {
        ReentrantLock reentrantLock = this.f8182g;
        reentrantLock.lock();
        try {
            C2975x m3495z = m3495z(C2979b.f8158a);
            Unit unit = Unit.INSTANCE;
            reentrantLock.unlock();
            super.mo3465w(z);
            if (m3495z != null) {
                throw m3495z;
            }
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    @Nullable
    /* renamed from: x */
    public Object mo3466x() {
        ReentrantLock reentrantLock = this.f8182g;
        reentrantLock.lock();
        try {
            Object obj = this.f8183h;
            C2970s c2970s = C2979b.f8158a;
            if (obj != c2970s) {
                this.f8183h = c2970s;
                Unit unit = Unit.INSTANCE;
                return obj;
            }
            Object m3477g = m3477g();
            if (m3477g == null) {
                m3477g = C2979b.f8161d;
            }
            return m3477g;
        } finally {
            reentrantLock.unlock();
        }
    }

    /* renamed from: z */
    public final C2975x m3495z(Object obj) {
        Function1<E, Unit> function1;
        Object obj2 = this.f8183h;
        C2975x c2975x = null;
        if (obj2 != C2979b.f8158a && (function1 = this.f8166f) != null) {
            c2975x = C2354n.m2506q(function1, obj2, null, 2);
        }
        this.f8183h = obj;
        return c2975x;
    }
}
