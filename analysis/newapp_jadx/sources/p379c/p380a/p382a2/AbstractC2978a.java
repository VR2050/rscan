package p379c.p380a.p382a2;

import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.Boxing;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3051d;
import p379c.p380a.C3069j;
import p379c.p380a.C3072k;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.p381a.C2959h;
import p379c.p380a.p381a.C2960i;
import p379c.p380a.p381a.C2961j;
import p379c.p380a.p381a.C2965n;
import p379c.p380a.p381a.C2967p;
import p379c.p380a.p381a.C2969r;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p382a2.C3001x;

/* renamed from: c.a.a2.a */
/* loaded from: classes2.dex */
public abstract class AbstractC2978a<E> extends AbstractC2980c<E> implements InterfaceC2983f<E> {

    /* renamed from: c.a.a2.a$a */
    public static final class a<E> implements InterfaceC2984g<E> {

        /* renamed from: a */
        @Nullable
        public Object f8143a = C2979b.f8161d;

        /* renamed from: b */
        @JvmField
        @NotNull
        public final AbstractC2978a<E> f8144b;

        public a(@NotNull AbstractC2978a<E> abstractC2978a) {
            this.f8144b = abstractC2978a;
        }

        @Override // p379c.p380a.p382a2.InterfaceC2984g
        @Nullable
        /* renamed from: a */
        public Object mo3468a(@NotNull Continuation<? super Boolean> continuation) {
            Object obj = this.f8143a;
            C2970s c2970s = C2979b.f8161d;
            if (obj != c2970s) {
                return Boxing.boxBoolean(m3469b(obj));
            }
            Object mo3466x = this.f8144b.mo3466x();
            this.f8143a = mo3466x;
            if (mo3466x != c2970s) {
                return Boxing.boxBoolean(m3469b(mo3466x));
            }
            C3069j m2498n0 = C2354n.m2498n0(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation));
            d dVar = new d(this, m2498n0);
            while (true) {
                if (this.f8144b.mo3462t(dVar)) {
                    AbstractC2978a<E> abstractC2978a = this.f8144b;
                    Objects.requireNonNull(abstractC2978a);
                    m2498n0.mo3562f(abstractC2978a.new e(dVar));
                    break;
                }
                Object mo3466x2 = this.f8144b.mo3466x();
                this.f8143a = mo3466x2;
                if (mo3466x2 instanceof C2985h) {
                    C2985h c2985h = (C2985h) mo3466x2;
                    if (c2985h.f8181g == null) {
                        Boolean boxBoolean = Boxing.boxBoolean(false);
                        Result.Companion companion = Result.INSTANCE;
                        m2498n0.resumeWith(Result.m6055constructorimpl(boxBoolean));
                    } else {
                        Throwable m3493w = c2985h.m3493w();
                        Result.Companion companion2 = Result.INSTANCE;
                        m2498n0.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(m3493w)));
                    }
                } else if (mo3466x2 != C2979b.f8161d) {
                    Boolean boxBoolean2 = Boxing.boxBoolean(true);
                    Function1<E, Unit> function1 = this.f8144b.f8166f;
                    m2498n0.m3615y(boxBoolean2, m2498n0.f8428f, function1 != null ? new C2965n(function1, mo3466x2, m2498n0.f8415i) : null);
                }
            }
            Object m3612u = m2498n0.m3612u();
            if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(continuation);
            }
            return m3612u;
        }

        /* renamed from: b */
        public final boolean m3469b(Object obj) {
            if (!(obj instanceof C2985h)) {
                return true;
            }
            C2985h c2985h = (C2985h) obj;
            if (c2985h.f8181g == null) {
                return false;
            }
            Throwable m3493w = c2985h.m3493w();
            String str = C2969r.f8133a;
            throw m3493w;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // p379c.p380a.p382a2.InterfaceC2984g
        public E next() {
            E e2 = (E) this.f8143a;
            if (e2 instanceof C2985h) {
                Throwable m3493w = ((C2985h) e2).m3493w();
                String str = C2969r.f8133a;
                throw m3493w;
            }
            C2970s c2970s = C2979b.f8161d;
            if (e2 == c2970s) {
                throw new IllegalStateException("'hasNext' should be called prior to 'next' invocation");
            }
            this.f8143a = c2970s;
            return e2;
        }
    }

    /* renamed from: c.a.a2.a$b */
    public static class b<E> extends AbstractC2993p<E> {

        /* renamed from: g */
        @JvmField
        @NotNull
        public final InterfaceC3066i<Object> f8145g;

        /* renamed from: h */
        @JvmField
        public final int f8146h;

        public b(@NotNull InterfaceC3066i<Object> interfaceC3066i, int i2) {
            this.f8145g = interfaceC3066i;
            this.f8146h = i2;
        }

        @Override // p379c.p380a.p382a2.InterfaceC2995r
        /* renamed from: e */
        public void mo3470e(E e2) {
            this.f8145g.mo3567r(C3072k.f8424a);
        }

        @Override // p379c.p380a.p382a2.InterfaceC2995r
        @Nullable
        /* renamed from: f */
        public C2970s mo3471f(E e2, @Nullable C2961j.b bVar) {
            if (this.f8145g.mo3564h(this.f8146h != 2 ? e2 : new C3001x(e2), null, mo3473r(e2)) != null) {
                return C3072k.f8424a;
            }
            return null;
        }

        @Override // p379c.p380a.p382a2.AbstractC2993p
        /* renamed from: s */
        public void mo3472s(@NotNull C2985h<?> c2985h) {
            int i2 = this.f8146h;
            if (i2 == 1 && c2985h.f8181g == null) {
                InterfaceC3066i<Object> interfaceC3066i = this.f8145g;
                Result.Companion companion = Result.INSTANCE;
                interfaceC3066i.resumeWith(Result.m6055constructorimpl(null));
            } else {
                if (i2 == 2) {
                    InterfaceC3066i<Object> interfaceC3066i2 = this.f8145g;
                    C3001x c3001x = new C3001x(new C3001x.a(c2985h.f8181g));
                    Result.Companion companion2 = Result.INSTANCE;
                    interfaceC3066i2.resumeWith(Result.m6055constructorimpl(c3001x));
                    return;
                }
                InterfaceC3066i<Object> interfaceC3066i3 = this.f8145g;
                Throwable m3493w = c2985h.m3493w();
                Result.Companion companion3 = Result.INSTANCE;
                interfaceC3066i3.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(m3493w)));
            }
        }

        @Override // p379c.p380a.p381a.C2961j
        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("ReceiveElement@");
            m586H.append(C2354n.m2495m0(this));
            m586H.append("[receiveMode=");
            return C1499a.m579A(m586H, this.f8146h, ']');
        }
    }

    /* renamed from: c.a.a2.a$c */
    public static final class c<E> extends b<E> {

        /* renamed from: i */
        @JvmField
        @NotNull
        public final Function1<E, Unit> f8147i;

        /* JADX WARN: Multi-variable type inference failed */
        public c(@NotNull InterfaceC3066i<Object> interfaceC3066i, int i2, @NotNull Function1<? super E, Unit> function1) {
            super(interfaceC3066i, i2);
            this.f8147i = function1;
        }

        @Override // p379c.p380a.p382a2.AbstractC2993p
        @Nullable
        /* renamed from: r */
        public Function1<Throwable, Unit> mo3473r(E e2) {
            return new C2965n(this.f8147i, e2, this.f8145g.get$context());
        }
    }

    /* renamed from: c.a.a2.a$d */
    public static class d<E> extends AbstractC2993p<E> {

        /* renamed from: g */
        @JvmField
        @NotNull
        public final a<E> f8148g;

        /* renamed from: h */
        @JvmField
        @NotNull
        public final InterfaceC3066i<Boolean> f8149h;

        /* JADX WARN: Multi-variable type inference failed */
        public d(@NotNull a<E> aVar, @NotNull InterfaceC3066i<? super Boolean> interfaceC3066i) {
            this.f8148g = aVar;
            this.f8149h = interfaceC3066i;
        }

        @Override // p379c.p380a.p382a2.InterfaceC2995r
        /* renamed from: e */
        public void mo3470e(E e2) {
            this.f8148g.f8143a = e2;
            this.f8149h.mo3567r(C3072k.f8424a);
        }

        @Override // p379c.p380a.p382a2.InterfaceC2995r
        @Nullable
        /* renamed from: f */
        public C2970s mo3471f(E e2, @Nullable C2961j.b bVar) {
            if (this.f8149h.mo3564h(Boolean.TRUE, null, mo3473r(e2)) != null) {
                return C3072k.f8424a;
            }
            return null;
        }

        @Override // p379c.p380a.p382a2.AbstractC2993p
        @Nullable
        /* renamed from: r */
        public Function1<Throwable, Unit> mo3473r(E e2) {
            Function1<E, Unit> function1 = this.f8148g.f8144b.f8166f;
            if (function1 != null) {
                return new C2965n(function1, e2, this.f8149h.get$context());
            }
            return null;
        }

        @Override // p379c.p380a.p382a2.AbstractC2993p
        /* renamed from: s */
        public void mo3472s(@NotNull C2985h<?> c2985h) {
            Object mo3561a = c2985h.f8181g == null ? this.f8149h.mo3561a(Boolean.FALSE, null) : this.f8149h.mo3563g(c2985h.m3493w());
            if (mo3561a != null) {
                this.f8148g.f8143a = c2985h;
                this.f8149h.mo3567r(mo3561a);
            }
        }

        @Override // p379c.p380a.p381a.C2961j
        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("ReceiveHasNext@");
            m586H.append(C2354n.m2495m0(this));
            return m586H.toString();
        }
    }

    /* renamed from: c.a.a2.a$e */
    public final class e extends AbstractC3051d {

        /* renamed from: c */
        public final AbstractC2993p<?> f8150c;

        public e(@NotNull AbstractC2993p<?> abstractC2993p) {
            this.f8150c = abstractC2993p;
        }

        @Override // p379c.p380a.AbstractC3063h
        /* renamed from: a */
        public void mo3456a(@Nullable Throwable th) {
            if (this.f8150c.mo3424o()) {
                Objects.requireNonNull(AbstractC2978a.this);
            }
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Throwable th) {
            if (this.f8150c.mo3424o()) {
                Objects.requireNonNull(AbstractC2978a.this);
            }
            return Unit.INSTANCE;
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("RemoveReceiveOnCancel[");
            m586H.append(this.f8150c);
            m586H.append(']');
            return m586H.toString();
        }
    }

    /* renamed from: c.a.a2.a$f */
    public static final class f extends C2961j.a {

        /* renamed from: d */
        public final /* synthetic */ AbstractC2978a f8152d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public f(C2961j c2961j, C2961j c2961j2, AbstractC2978a abstractC2978a) {
            super(c2961j2);
            this.f8152d = abstractC2978a;
        }

        @Override // p379c.p380a.p381a.AbstractC2955d
        /* renamed from: c */
        public Object mo3417c(C2961j c2961j) {
            if (this.f8152d.mo3464v()) {
                return null;
            }
            return C2960i.f8110a;
        }
    }

    @DebugMetadata(m5319c = "kotlinx.coroutines.channels.AbstractChannel", m5320f = "AbstractChannel.kt", m5321i = {0, 0}, m5322l = {624}, m5323m = "receiveOrClosed-ZYPwvRU", m5324n = {"this", "result"}, m5325s = {"L$0", "L$1"})
    /* renamed from: c.a.a2.a$g */
    public static final class g extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8153c;

        /* renamed from: e */
        public int f8154e;

        /* renamed from: g */
        public Object f8156g;

        /* renamed from: h */
        public Object f8157h;

        public g(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8153c = obj;
            this.f8154e |= Integer.MIN_VALUE;
            return AbstractC2978a.this.mo3460n(this);
        }
    }

    public AbstractC2978a(@Nullable Function1<? super E, Unit> function1) {
        super(function1);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: c */
    public boolean mo3457c() {
        C2961j m3429k = this.f8165e.m3429k();
        C2985h<?> c2985h = null;
        if (!(m3429k instanceof C2985h)) {
            m3429k = null;
        }
        C2985h<?> c2985h2 = (C2985h) m3429k;
        if (c2985h2 != null) {
            m3478h(c2985h2);
            c2985h = c2985h2;
        }
        return c2985h != null && mo3464v();
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: d */
    public final void mo3458d(@Nullable CancellationException cancellationException) {
        if (cancellationException == null) {
            cancellationException = new CancellationException(getClass().getSimpleName() + " was cancelled");
        }
        mo3465w(mo3480j(cancellationException));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p379c.p380a.p382a2.InterfaceC2994q
    @Nullable
    /* renamed from: e */
    public final Object mo3459e(@NotNull Continuation<? super E> continuation) {
        Object mo3466x = mo3466x();
        return (mo3466x == C2979b.f8161d || (mo3466x instanceof C2985h)) ? m3467y(1, continuation) : mo3466x;
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    @NotNull
    public final InterfaceC2984g<E> iterator() {
        return new a(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0035  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
    @Override // p379c.p380a.p382a2.InterfaceC2994q
    @org.jetbrains.annotations.Nullable
    /* renamed from: n */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object mo3460n(@org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super p379c.p380a.p382a2.C3001x<? extends E>> r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof p379c.p380a.p382a2.AbstractC2978a.g
            if (r0 == 0) goto L13
            r0 = r5
            c.a.a2.a$g r0 = (p379c.p380a.p382a2.AbstractC2978a.g) r0
            int r1 = r0.f8154e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8154e = r1
            goto L18
        L13:
            c.a.a2.a$g r0 = new c.a.a2.a$g
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.f8153c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8154e
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.lang.Object r0 = r0.f8156g
            c.a.a2.a r0 = (p379c.p380a.p382a2.AbstractC2978a) r0
            kotlin.ResultKt.throwOnFailure(r5)
            goto L5d
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L35:
            kotlin.ResultKt.throwOnFailure(r5)
            java.lang.Object r5 = r4.mo3466x()
            c.a.a.s r2 = p379c.p380a.p382a2.C2979b.f8161d
            if (r5 == r2) goto L4f
            boolean r0 = r5 instanceof p379c.p380a.p382a2.C2985h
            if (r0 == 0) goto L4e
            c.a.a2.h r5 = (p379c.p380a.p382a2.C2985h) r5
            java.lang.Throwable r5 = r5.f8181g
            c.a.a2.x$a r0 = new c.a.a2.x$a
            r0.<init>(r5)
            r5 = r0
        L4e:
            return r5
        L4f:
            r2 = 2
            r0.f8156g = r4
            r0.f8157h = r5
            r0.f8154e = r3
            java.lang.Object r5 = r4.m3467y(r2, r0)
            if (r5 != r1) goto L5d
            return r1
        L5d:
            c.a.a2.x r5 = (p379c.p380a.p382a2.C3001x) r5
            java.lang.Object r5 = r5.f8188a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p382a2.AbstractC2978a.mo3460n(kotlin.coroutines.Continuation):java.lang.Object");
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    @Nullable
    /* renamed from: r */
    public InterfaceC2995r<E> mo3461r() {
        InterfaceC2995r<E> mo3461r = super.mo3461r();
        if (mo3461r != null) {
            boolean z = mo3461r instanceof C2985h;
        }
        return mo3461r;
    }

    /* renamed from: t */
    public boolean mo3462t(@NotNull AbstractC2993p<? super E> abstractC2993p) {
        int m3433q;
        C2961j m3430l;
        if (!mo3463u()) {
            C2961j c2961j = this.f8165e;
            f fVar = new f(abstractC2993p, abstractC2993p, this);
            do {
                C2961j m3430l2 = c2961j.m3430l();
                if (!(!(m3430l2 instanceof AbstractC2997t))) {
                    break;
                }
                m3433q = m3430l2.m3433q(abstractC2993p, c2961j, fVar);
                if (m3433q == 1) {
                    return true;
                }
            } while (m3433q != 2);
        } else {
            C2961j c2961j2 = this.f8165e;
            do {
                m3430l = c2961j2.m3430l();
                if (!(!(m3430l instanceof AbstractC2997t))) {
                }
            } while (!m3430l.m3425g(abstractC2993p, c2961j2));
            return true;
        }
        return false;
    }

    /* renamed from: u */
    public abstract boolean mo3463u();

    /* renamed from: v */
    public abstract boolean mo3464v();

    /* renamed from: w */
    public void mo3465w(boolean z) {
        C2985h<?> m3477g = m3477g();
        if (m3477g == null) {
            throw new IllegalStateException("Cannot happen".toString());
        }
        Object obj = null;
        while (true) {
            C2961j m3430l = m3477g.m3430l();
            if (m3430l instanceof C2959h) {
                break;
            }
            if (m3430l.mo3424o()) {
                obj = C2354n.m2496m1(obj, (AbstractC2997t) m3430l);
            } else {
                Object m3428j = m3430l.m3428j();
                Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Removed");
                ((C2967p) m3428j).f8131a.m3426h(null);
            }
        }
        if (obj == null) {
            return;
        }
        if (!(obj instanceof ArrayList)) {
            ((AbstractC2997t) obj).mo3489t(m3477g);
            return;
        }
        ArrayList arrayList = (ArrayList) obj;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                return;
            } else {
                ((AbstractC2997t) arrayList.get(size)).mo3489t(m3477g);
            }
        }
    }

    @Nullable
    /* renamed from: x */
    public Object mo3466x() {
        while (true) {
            AbstractC2997t m3486s = m3486s();
            if (m3486s == null) {
                return C2979b.f8161d;
            }
            if (m3486s.mo3490u(null) != null) {
                m3486s.mo3487r();
                return m3486s.mo3488s();
            }
            m3486s.mo3502v();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Nullable
    /* renamed from: y */
    public final <R> Object m3467y(int i2, @NotNull Continuation<? super R> continuation) {
        C3069j m2498n0 = C2354n.m2498n0(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation));
        b bVar = this.f8166f == null ? new b(m2498n0, i2) : new c(m2498n0, i2, this.f8166f);
        while (true) {
            if (mo3462t(bVar)) {
                m2498n0.mo3562f(new e(bVar));
                break;
            }
            Object mo3466x = mo3466x();
            if (mo3466x instanceof C2985h) {
                bVar.mo3472s((C2985h) mo3466x);
                break;
            }
            if (mo3466x != C2979b.f8161d) {
                m2498n0.m3615y(bVar.f8146h != 2 ? mo3466x : new C3001x(mo3466x), m2498n0.f8428f, bVar.mo3473r(mo3466x));
            }
        }
        Object m3612u = m2498n0.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3612u;
    }
}
