package p379c.p380a.p381a;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.PublishedApi;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a.j */
/* loaded from: classes2.dex */
public class C2961j {

    /* renamed from: c */
    public static final AtomicReferenceFieldUpdater f8111c = AtomicReferenceFieldUpdater.newUpdater(C2961j.class, Object.class, "_next");

    /* renamed from: e */
    public static final AtomicReferenceFieldUpdater f8112e = AtomicReferenceFieldUpdater.newUpdater(C2961j.class, Object.class, "_prev");

    /* renamed from: f */
    public static final AtomicReferenceFieldUpdater f8113f = AtomicReferenceFieldUpdater.newUpdater(C2961j.class, Object.class, "_removedRef");
    public volatile Object _next = this;
    public volatile Object _prev = this;
    public volatile Object _removedRef = null;

    @PublishedApi
    /* renamed from: c.a.a.j$a */
    public static abstract class a extends AbstractC2955d<C2961j> {

        /* renamed from: b */
        @JvmField
        @Nullable
        public C2961j f8114b;

        /* renamed from: c */
        @JvmField
        @NotNull
        public final C2961j f8115c;

        public a(@NotNull C2961j c2961j) {
            this.f8115c = c2961j;
        }

        @Override // p379c.p380a.p381a.AbstractC2955d
        /* renamed from: b */
        public void mo3416b(C2961j c2961j, Object obj) {
            C2961j c2961j2 = c2961j;
            boolean z = obj == null;
            C2961j c2961j3 = z ? this.f8115c : this.f8114b;
            if (c2961j3 != null && C2961j.f8111c.compareAndSet(c2961j2, this, c2961j3) && z) {
                C2961j c2961j4 = this.f8115c;
                C2961j c2961j5 = this.f8114b;
                Intrinsics.checkNotNull(c2961j5);
                c2961j4.m3427i(c2961j5);
            }
        }
    }

    /* renamed from: c.a.a.j$b */
    public static final class b extends AbstractC2966o {
    }

    @PublishedApi
    /* renamed from: g */
    public final boolean m3425g(@NotNull C2961j c2961j, @NotNull C2961j c2961j2) {
        f8112e.lazySet(c2961j, this);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f8111c;
        atomicReferenceFieldUpdater.lazySet(c2961j, c2961j2);
        if (!atomicReferenceFieldUpdater.compareAndSet(this, c2961j2, c2961j)) {
            return false;
        }
        c2961j.m3427i(c2961j2);
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x003c, code lost:
    
        if (p379c.p380a.p381a.C2961j.f8111c.compareAndSet(r2, r1, ((p379c.p380a.p381a.C2967p) r3).f8131a) != false) goto L26;
     */
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p379c.p380a.p381a.C2961j m3426h(p379c.p380a.p381a.AbstractC2966o r7) {
        /*
            r6 = this;
        L0:
            java.lang.Object r7 = r6._prev
            c.a.a.j r7 = (p379c.p380a.p381a.C2961j) r7
            r0 = 0
            r1 = r7
        L6:
            r2 = r0
        L7:
            java.lang.Object r3 = r1._next
            if (r3 != r6) goto L18
            if (r7 != r1) goto Le
            return r1
        Le:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = p379c.p380a.p381a.C2961j.f8112e
            boolean r7 = r0.compareAndSet(r6, r7, r1)
            if (r7 != 0) goto L17
            goto L0
        L17:
            return r1
        L18:
            boolean r4 = r6.mo3423n()
            if (r4 == 0) goto L1f
            return r0
        L1f:
            if (r3 != 0) goto L22
            return r1
        L22:
            boolean r4 = r3 instanceof p379c.p380a.p381a.AbstractC2966o
            if (r4 == 0) goto L2c
            c.a.a.o r3 = (p379c.p380a.p381a.AbstractC2966o) r3
            r3.mo3415a(r1)
            goto L0
        L2c:
            boolean r4 = r3 instanceof p379c.p380a.p381a.C2967p
            if (r4 == 0) goto L46
            if (r2 == 0) goto L41
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r4 = p379c.p380a.p381a.C2961j.f8111c
            c.a.a.p r3 = (p379c.p380a.p381a.C2967p) r3
            c.a.a.j r3 = r3.f8131a
            boolean r1 = r4.compareAndSet(r2, r1, r3)
            if (r1 != 0) goto L3f
            goto L0
        L3f:
            r1 = r2
            goto L6
        L41:
            java.lang.Object r1 = r1._prev
            c.a.a.j r1 = (p379c.p380a.p381a.C2961j) r1
            goto L7
        L46:
        */
        //  java.lang.String r2 = "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */"
        /*
            java.util.Objects.requireNonNull(r3, r2)
            r2 = r3
            c.a.a.j r2 = (p379c.p380a.p381a.C2961j) r2
            r5 = r2
            r2 = r1
            r1 = r5
            goto L7
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p381a.C2961j.m3426h(c.a.a.o):c.a.a.j");
    }

    /* renamed from: i */
    public final void m3427i(C2961j c2961j) {
        C2961j c2961j2;
        do {
            c2961j2 = (C2961j) c2961j._prev;
            if (m3428j() != c2961j) {
                return;
            }
        } while (!f8112e.compareAndSet(c2961j, c2961j2, this));
        if (mo3423n()) {
            c2961j.m3426h(null);
        }
    }

    @NotNull
    /* renamed from: j */
    public final Object m3428j() {
        while (true) {
            Object obj = this._next;
            if (!(obj instanceof AbstractC2966o)) {
                return obj;
            }
            ((AbstractC2966o) obj).mo3415a(this);
        }
    }

    @NotNull
    /* renamed from: k */
    public final C2961j m3429k() {
        C2961j c2961j;
        Object m3428j = m3428j();
        C2967p c2967p = (C2967p) (!(m3428j instanceof C2967p) ? null : m3428j);
        if (c2967p != null && (c2961j = c2967p.f8131a) != null) {
            return c2961j;
        }
        Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
        return (C2961j) m3428j;
    }

    @NotNull
    /* renamed from: l */
    public final C2961j m3430l() {
        C2961j m3426h = m3426h(null);
        if (m3426h == null) {
            Object obj = this._prev;
            while (true) {
                m3426h = (C2961j) obj;
                if (!m3426h.mo3423n()) {
                    break;
                }
                obj = m3426h._prev;
            }
        }
        return m3426h;
    }

    @PublishedApi
    /* renamed from: m */
    public final void m3431m() {
        C2961j c2961j = this;
        while (true) {
            Object m3428j = c2961j.m3428j();
            if (!(m3428j instanceof C2967p)) {
                c2961j.m3426h(null);
                return;
            }
            c2961j = ((C2967p) m3428j).f8131a;
        }
    }

    /* renamed from: n */
    public boolean mo3423n() {
        return m3428j() instanceof C2967p;
    }

    /* renamed from: o */
    public boolean mo3424o() {
        return m3432p() == null;
    }

    @PublishedApi
    @Nullable
    /* renamed from: p */
    public final C2961j m3432p() {
        Object m3428j;
        C2961j c2961j;
        C2967p c2967p;
        do {
            m3428j = m3428j();
            if (m3428j instanceof C2967p) {
                return ((C2967p) m3428j).f8131a;
            }
            if (m3428j == this) {
                return (C2961j) m3428j;
            }
            Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
            c2961j = (C2961j) m3428j;
            c2967p = (C2967p) c2961j._removedRef;
            if (c2967p == null) {
                c2967p = new C2967p(c2961j);
                f8113f.lazySet(c2961j, c2967p);
            }
        } while (!f8111c.compareAndSet(this, m3428j, c2967p));
        c2961j.m3426h(null);
        return null;
    }

    @PublishedApi
    /* renamed from: q */
    public final int m3433q(@NotNull C2961j c2961j, @NotNull C2961j c2961j2, @NotNull a aVar) {
        f8112e.lazySet(c2961j, this);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f8111c;
        atomicReferenceFieldUpdater.lazySet(c2961j, c2961j2);
        aVar.f8114b = c2961j2;
        if (atomicReferenceFieldUpdater.compareAndSet(this, c2961j2, aVar)) {
            return aVar.mo3415a(this) == null ? 1 : 2;
        }
        return 0;
    }

    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '@' + Integer.toHexString(System.identityHashCode(this));
    }
}
