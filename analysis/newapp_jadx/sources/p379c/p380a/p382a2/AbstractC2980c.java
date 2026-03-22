package p379c.p380a.p382a2;

import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.ExceptionsKt__ExceptionsKt;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3069j;
import p379c.p380a.C3072k;
import p379c.p380a.C3092q1;
import p379c.p380a.p381a.C2959h;
import p379c.p380a.p381a.C2960i;
import p379c.p380a.p381a.C2961j;
import p379c.p380a.p381a.C2967p;
import p379c.p380a.p381a.C2969r;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p381a.C2975x;

/* renamed from: c.a.a2.c */
/* loaded from: classes2.dex */
public abstract class AbstractC2980c<E> implements InterfaceC2998u<E> {

    /* renamed from: c */
    public static final AtomicReferenceFieldUpdater f8164c = AtomicReferenceFieldUpdater.newUpdater(AbstractC2980c.class, Object.class, "onCloseHandler");

    /* renamed from: f */
    @JvmField
    @Nullable
    public final Function1<E, Unit> f8166f;

    /* renamed from: e */
    @NotNull
    public final C2959h f8165e = new C2959h();
    public volatile Object onCloseHandler = null;

    /* renamed from: c.a.a2.c$a */
    public static final class a<E> extends AbstractC2997t {

        /* renamed from: g */
        @JvmField
        public final E f8167g;

        public a(E e2) {
            this.f8167g = e2;
        }

        @Override // p379c.p380a.p382a2.AbstractC2997t
        /* renamed from: r */
        public void mo3487r() {
        }

        @Override // p379c.p380a.p382a2.AbstractC2997t
        @Nullable
        /* renamed from: s */
        public Object mo3488s() {
            return this.f8167g;
        }

        @Override // p379c.p380a.p382a2.AbstractC2997t
        /* renamed from: t */
        public void mo3489t(@NotNull C2985h<?> c2985h) {
        }

        @Override // p379c.p380a.p381a.C2961j
        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("SendBuffered@");
            m586H.append(C2354n.m2495m0(this));
            m586H.append('(');
            m586H.append(this.f8167g);
            m586H.append(')');
            return m586H.toString();
        }

        @Override // p379c.p380a.p382a2.AbstractC2997t
        @Nullable
        /* renamed from: u */
        public C2970s mo3490u(@Nullable C2961j.b bVar) {
            return C3072k.f8424a;
        }
    }

    /* renamed from: c.a.a2.c$b */
    public static final class b extends C2961j.a {

        /* renamed from: d */
        public final /* synthetic */ AbstractC2980c f8168d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(C2961j c2961j, C2961j c2961j2, AbstractC2980c abstractC2980c) {
            super(c2961j2);
            this.f8168d = abstractC2980c;
        }

        @Override // p379c.p380a.p381a.AbstractC2955d
        /* renamed from: c */
        public Object mo3417c(C2961j c2961j) {
            if (this.f8168d.mo3483o()) {
                return null;
            }
            return C2960i.f8110a;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public AbstractC2980c(@Nullable Function1<? super E, Unit> function1) {
        this.f8166f = function1;
    }

    /* renamed from: a */
    public static final void m3474a(AbstractC2980c abstractC2980c, Continuation continuation, Object obj, C2985h c2985h) {
        C2975x m2506q;
        abstractC2980c.m3478h(c2985h);
        Throwable m3494x = c2985h.m3494x();
        Function1<E, Unit> function1 = abstractC2980c.f8166f;
        if (function1 == null || (m2506q = C2354n.m2506q(function1, obj, null, 2)) == null) {
            Result.Companion companion = Result.INSTANCE;
            ((C3069j) continuation).resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(m3494x)));
        } else {
            ExceptionsKt__ExceptionsKt.addSuppressed(m2506q, m3494x);
            Result.Companion companion2 = Result.INSTANCE;
            ((C3069j) continuation).resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(m2506q)));
        }
    }

    @Nullable
    /* renamed from: b */
    public Object mo3475b(@NotNull AbstractC2997t abstractC2997t) {
        boolean z;
        C2961j m3430l;
        if (mo3481l()) {
            C2961j c2961j = this.f8165e;
            do {
                m3430l = c2961j.m3430l();
                if (m3430l instanceof InterfaceC2995r) {
                    return m3430l;
                }
            } while (!m3430l.m3425g(abstractC2997t, c2961j));
            return null;
        }
        C2961j c2961j2 = this.f8165e;
        b bVar = new b(abstractC2997t, abstractC2997t, this);
        while (true) {
            C2961j m3430l2 = c2961j2.m3430l();
            if (!(m3430l2 instanceof InterfaceC2995r)) {
                int m3433q = m3430l2.m3433q(abstractC2997t, c2961j2, bVar);
                z = true;
                if (m3433q != 1) {
                    if (m3433q == 2) {
                        z = false;
                        break;
                    }
                } else {
                    break;
                }
            } else {
                return m3430l2;
            }
        }
        if (z) {
            return null;
        }
        return C2979b.f8162e;
    }

    @NotNull
    /* renamed from: f */
    public String mo3476f() {
        return "";
    }

    @Nullable
    /* renamed from: g */
    public final C2985h<?> m3477g() {
        C2961j m3430l = this.f8165e.m3430l();
        if (!(m3430l instanceof C2985h)) {
            m3430l = null;
        }
        C2985h<?> c2985h = (C2985h) m3430l;
        if (c2985h == null) {
            return null;
        }
        m3478h(c2985h);
        return c2985h;
    }

    /* renamed from: h */
    public final void m3478h(C2985h<?> c2985h) {
        Object obj = null;
        while (true) {
            C2961j m3430l = c2985h.m3430l();
            if (!(m3430l instanceof AbstractC2993p)) {
                m3430l = null;
            }
            AbstractC2993p abstractC2993p = (AbstractC2993p) m3430l;
            if (abstractC2993p == null) {
                break;
            }
            if (abstractC2993p.mo3424o()) {
                obj = C2354n.m2496m1(obj, abstractC2993p);
            } else {
                Object m3428j = abstractC2993p.m3428j();
                Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Removed");
                ((C2967p) m3428j).f8131a.m3426h(null);
            }
        }
        if (obj == null) {
            return;
        }
        if (!(obj instanceof ArrayList)) {
            ((AbstractC2993p) obj).mo3472s(c2985h);
            return;
        }
        ArrayList arrayList = (ArrayList) obj;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                return;
            } else {
                ((AbstractC2993p) arrayList.get(size)).mo3472s(c2985h);
            }
        }
    }

    /* renamed from: i */
    public final Throwable m3479i(E e2, C2985h<?> c2985h) {
        C2975x m2506q;
        m3478h(c2985h);
        Function1<E, Unit> function1 = this.f8166f;
        if (function1 == null || (m2506q = C2354n.m2506q(function1, e2, null, 2)) == null) {
            return c2985h.m3494x();
        }
        ExceptionsKt__ExceptionsKt.addSuppressed(m2506q, c2985h.m3494x());
        throw m2506q;
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    /* renamed from: j */
    public boolean mo3480j(@Nullable Throwable th) {
        boolean z;
        Object obj;
        C2970s c2970s;
        C2985h<?> c2985h = new C2985h<>(th);
        C2961j c2961j = this.f8165e;
        while (true) {
            C2961j m3430l = c2961j.m3430l();
            if (!(!(m3430l instanceof C2985h))) {
                z = false;
                break;
            }
            if (m3430l.m3425g(c2985h, c2961j)) {
                z = true;
                break;
            }
        }
        if (!z) {
            c2985h = (C2985h) this.f8165e.m3430l();
        }
        m3478h(c2985h);
        if (z && (obj = this.onCloseHandler) != null && obj != (c2970s = C2979b.f8163f) && f8164c.compareAndSet(this, obj, c2970s)) {
            ((Function1) TypeIntrinsics.beforeCheckcastToFunctionOfArity(obj, 1)).invoke(th);
        }
        return z;
    }

    /* renamed from: l */
    public abstract boolean mo3481l();

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    /* renamed from: m */
    public void mo3482m(@NotNull Function1<? super Throwable, Unit> function1) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f8164c;
        if (!atomicReferenceFieldUpdater.compareAndSet(this, null, function1)) {
            Object obj = this.onCloseHandler;
            if (obj != C2979b.f8163f) {
                throw new IllegalStateException(C1499a.m636v("Another handler was already registered: ", obj));
            }
            throw new IllegalStateException("Another handler was already registered and successfully invoked");
        }
        C2985h<?> m3477g = m3477g();
        if (m3477g == null || !atomicReferenceFieldUpdater.compareAndSet(this, function1, C2979b.f8163f)) {
            return;
        }
        function1.invoke(m3477g.f8181g);
    }

    /* renamed from: o */
    public abstract boolean mo3483o();

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    public final boolean offer(E e2) {
        Object mo3485q = mo3485q(e2);
        if (mo3485q == C2979b.f8159b) {
            return true;
        }
        if (mo3485q != C2979b.f8160c) {
            if (!(mo3485q instanceof C2985h)) {
                throw new IllegalStateException(C1499a.m636v("offerInternal returned ", mo3485q).toString());
            }
            Throwable m3479i = m3479i(e2, (C2985h) mo3485q);
            String str = C2969r.f8133a;
            throw m3479i;
        }
        C2985h<?> m3477g = m3477g();
        if (m3477g == null) {
            return false;
        }
        Throwable m3479i2 = m3479i(e2, m3477g);
        String str2 = C2969r.f8133a;
        throw m3479i2;
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    @Nullable
    /* renamed from: p */
    public final Object mo3484p(E e2, @NotNull Continuation<? super Unit> continuation) {
        if (mo3485q(e2) == C2979b.f8159b) {
            return Unit.INSTANCE;
        }
        C3069j m2498n0 = C2354n.m2498n0(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation));
        while (true) {
            if (!(this.f8165e.m3429k() instanceof InterfaceC2995r) && mo3483o()) {
                AbstractC2997t c2999v = this.f8166f == null ? new C2999v(e2, m2498n0) : new C3000w(e2, m2498n0, this.f8166f);
                Object mo3475b = mo3475b(c2999v);
                if (mo3475b == null) {
                    m2498n0.mo3562f(new C3092q1(c2999v));
                    break;
                }
                if (mo3475b instanceof C2985h) {
                    m3474a(this, m2498n0, e2, (C2985h) mo3475b);
                    break;
                }
                if (mo3475b != C2979b.f8162e && !(mo3475b instanceof AbstractC2993p)) {
                    throw new IllegalStateException(C1499a.m636v("enqueueSend returned ", mo3475b).toString());
                }
            }
            Object mo3485q = mo3485q(e2);
            if (mo3485q == C2979b.f8159b) {
                Unit unit = Unit.INSTANCE;
                Result.Companion companion = Result.INSTANCE;
                m2498n0.resumeWith(Result.m6055constructorimpl(unit));
                break;
            }
            if (mo3485q != C2979b.f8160c) {
                if (!(mo3485q instanceof C2985h)) {
                    throw new IllegalStateException(C1499a.m636v("offerInternal returned ", mo3485q).toString());
                }
                m3474a(this, m2498n0, e2, (C2985h) mo3485q);
            }
        }
        Object m3612u = m2498n0.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m3612u : Unit.INSTANCE;
    }

    @NotNull
    /* renamed from: q */
    public Object mo3485q(E e2) {
        InterfaceC2995r<E> mo3461r;
        do {
            mo3461r = mo3461r();
            if (mo3461r == null) {
                return C2979b.f8160c;
            }
        } while (mo3461r.mo3471f(e2, null) == null);
        mo3461r.mo3470e(e2);
        return mo3461r.mo3492a();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [c.a.a.j] */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v3 */
    @Nullable
    /* renamed from: r */
    public InterfaceC2995r<E> mo3461r() {
        ?? r1;
        C2961j m3432p;
        C2959h c2959h = this.f8165e;
        while (true) {
            Object m3428j = c2959h.m3428j();
            Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
            r1 = (C2961j) m3428j;
            if (r1 != c2959h && (r1 instanceof InterfaceC2995r)) {
                if (((((InterfaceC2995r) r1) instanceof C2985h) && !r1.mo3423n()) || (m3432p = r1.m3432p()) == null) {
                    break;
                }
                m3432p.m3431m();
            }
        }
        r1 = 0;
        return (InterfaceC2995r) r1;
    }

    @Nullable
    /* renamed from: s */
    public final AbstractC2997t m3486s() {
        C2961j c2961j;
        C2961j m3432p;
        C2959h c2959h = this.f8165e;
        while (true) {
            Object m3428j = c2959h.m3428j();
            Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
            c2961j = (C2961j) m3428j;
            if (c2961j != c2959h && (c2961j instanceof AbstractC2997t)) {
                if (((((AbstractC2997t) c2961j) instanceof C2985h) && !c2961j.mo3423n()) || (m3432p = c2961j.m3432p()) == null) {
                    break;
                }
                m3432p.m3431m();
            }
        }
        c2961j = null;
        return (AbstractC2997t) c2961j;
    }

    @NotNull
    public String toString() {
        String str;
        String str2;
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append('@');
        sb.append(C2354n.m2495m0(this));
        sb.append('{');
        C2961j m3429k = this.f8165e.m3429k();
        if (m3429k == this.f8165e) {
            str2 = "EmptyQueue";
        } else {
            if (m3429k instanceof C2985h) {
                str = m3429k.toString();
            } else if (m3429k instanceof AbstractC2993p) {
                str = "ReceiveQueued";
            } else if (m3429k instanceof AbstractC2997t) {
                str = "SendQueued";
            } else {
                str = "UNEXPECTED:" + m3429k;
            }
            C2961j m3430l = this.f8165e.m3430l();
            if (m3430l != m3429k) {
                StringBuilder m590L = C1499a.m590L(str, ",queueSize=");
                Object m3428j = this.f8165e.m3428j();
                Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
                int i2 = 0;
                for (C2961j c2961j = (C2961j) m3428j; !Intrinsics.areEqual(c2961j, r2); c2961j = c2961j.m3429k()) {
                    i2++;
                }
                m590L.append(i2);
                str2 = m590L.toString();
                if (m3430l instanceof C2985h) {
                    str2 = str2 + ",closedForSend=" + m3430l;
                }
            } else {
                str2 = str;
            }
        }
        sb.append(str2);
        sb.append('}');
        sb.append(mo3476f());
        return sb.toString();
    }
}
