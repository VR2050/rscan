package p379c.p380a;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.ExceptionsKt__ExceptionsKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.AbstractC2966o;
import p379c.p380a.p381a.C2960i;
import p379c.p380a.p381a.C2961j;

@Deprecated(level = DeprecationLevel.ERROR, message = "This is internal API and may be removed in the future releases")
/* renamed from: c.a.i1 */
/* loaded from: classes2.dex */
public class C3068i1 implements InterfaceC3053d1, InterfaceC3087p, InterfaceC3089p1 {

    /* renamed from: c */
    public static final AtomicReferenceFieldUpdater f8404c = AtomicReferenceFieldUpdater.newUpdater(C3068i1.class, Object.class, "_state");
    public volatile Object _parentHandle;
    public volatile Object _state;

    /* renamed from: c.a.i1$a */
    public static final class a<T> extends C3069j<T> {

        /* renamed from: k */
        public final C3068i1 f8405k;

        public a(@NotNull Continuation<? super T> continuation, @NotNull C3068i1 c3068i1) {
            super(continuation, 1);
            this.f8405k = c3068i1;
        }

        @Override // p379c.p380a.C3069j
        @NotNull
        /* renamed from: t */
        public Throwable mo3595t(@NotNull InterfaceC3053d1 interfaceC3053d1) {
            Throwable th;
            Object m3576L = this.f8405k.m3576L();
            return (!(m3576L instanceof c) || (th = (Throwable) ((c) m3576L)._rootCause) == null) ? m3576L instanceof C3108w ? ((C3108w) m3576L).f8470b : interfaceC3053d1.mo3553q() : th;
        }

        @Override // p379c.p380a.C3069j
        @NotNull
        /* renamed from: x */
        public String mo3596x() {
            return "AwaitContinuation";
        }
    }

    /* renamed from: c.a.i1$b */
    public static final class b extends AbstractC3065h1<InterfaceC3053d1> {

        /* renamed from: h */
        public final C3068i1 f8406h;

        /* renamed from: i */
        public final c f8407i;

        /* renamed from: j */
        public final C3084o f8408j;

        /* renamed from: k */
        public final Object f8409k;

        public b(@NotNull C3068i1 c3068i1, @NotNull c cVar, @NotNull C3084o c3084o, @Nullable Object obj) {
            super(c3084o.f8434h);
            this.f8406h = c3068i1;
            this.f8407i = cVar;
            this.f8408j = c3084o;
            this.f8409k = obj;
        }

        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ Unit invoke(Throwable th) {
            mo3514r(th);
            return Unit.INSTANCE;
        }

        @Override // p379c.p380a.AbstractC3114y
        /* renamed from: r */
        public void mo3514r(@Nullable Throwable th) {
            C3068i1 c3068i1 = this.f8406h;
            c cVar = this.f8407i;
            C3084o c3084o = this.f8408j;
            Object obj = this.f8409k;
            C3084o m3582W = c3068i1.m3582W(c3084o);
            if (m3582W == null || !c3068i1.m3589g0(cVar, m3582W, obj)) {
                c3068i1.mo3446v(c3068i1.m3573G(cVar, obj));
            }
        }

        @Override // p379c.p380a.p381a.C2961j
        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("ChildCompletion[");
            m586H.append(this.f8408j);
            m586H.append(", ");
            m586H.append(this.f8409k);
            m586H.append(']');
            return m586H.toString();
        }
    }

    /* renamed from: c.a.i1$c */
    public static final class c implements InterfaceC3115y0 {
        public volatile Object _exceptionsHolder = null;
        public volatile int _isCompleting;
        public volatile Object _rootCause;

        /* renamed from: c */
        @NotNull
        public final C3080m1 f8410c;

        public c(@NotNull C3080m1 c3080m1, boolean z, @Nullable Throwable th) {
            this.f8410c = c3080m1;
            this._isCompleting = z ? 1 : 0;
            this._rootCause = th;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* renamed from: a */
        public final void m3597a(@NotNull Throwable th) {
            Throwable th2 = (Throwable) this._rootCause;
            if (th2 == null) {
                this._rootCause = th;
                return;
            }
            if (th == th2) {
                return;
            }
            Object obj = this._exceptionsHolder;
            if (obj == null) {
                this._exceptionsHolder = th;
                return;
            }
            if (!(obj instanceof Throwable)) {
                if (!(obj instanceof ArrayList)) {
                    throw new IllegalStateException(C1499a.m636v("State is ", obj).toString());
                }
                ((ArrayList) obj).add(th);
            } else {
                if (th == obj) {
                    return;
                }
                ArrayList<Throwable> m3598c = m3598c();
                m3598c.add(obj);
                m3598c.add(th);
                Unit unit = Unit.INSTANCE;
                this._exceptionsHolder = m3598c;
            }
        }

        @Override // p379c.p380a.InterfaceC3115y0
        /* renamed from: b */
        public boolean mo3559b() {
            return ((Throwable) this._rootCause) == null;
        }

        /* renamed from: c */
        public final ArrayList<Throwable> m3598c() {
            return new ArrayList<>(4);
        }

        @Override // p379c.p380a.InterfaceC3115y0
        @NotNull
        /* renamed from: d */
        public C3080m1 mo3560d() {
            return this.f8410c;
        }

        /* renamed from: e */
        public final boolean m3599e() {
            return ((Throwable) this._rootCause) != null;
        }

        /* renamed from: f */
        public final boolean m3600f() {
            return this._exceptionsHolder == C3071j1.f8421e;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @NotNull
        /* renamed from: g */
        public final List<Throwable> m3601g(@Nullable Throwable th) {
            ArrayList<Throwable> arrayList;
            Object obj = this._exceptionsHolder;
            if (obj == null) {
                arrayList = m3598c();
            } else if (obj instanceof Throwable) {
                ArrayList<Throwable> m3598c = m3598c();
                m3598c.add(obj);
                arrayList = m3598c;
            } else {
                if (!(obj instanceof ArrayList)) {
                    throw new IllegalStateException(C1499a.m636v("State is ", obj).toString());
                }
                arrayList = (ArrayList) obj;
            }
            Throwable th2 = (Throwable) this._rootCause;
            if (th2 != null) {
                arrayList.add(0, th2);
            }
            if (th != null && (!Intrinsics.areEqual(th, th2))) {
                arrayList.add(th);
            }
            this._exceptionsHolder = C3071j1.f8421e;
            return arrayList;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r1v2, types: [boolean, int] */
        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("Finishing[cancelling=");
            m586H.append(m3599e());
            m586H.append(", completing=");
            m586H.append((boolean) this._isCompleting);
            m586H.append(", rootCause=");
            m586H.append((Throwable) this._rootCause);
            m586H.append(", exceptions=");
            m586H.append(this._exceptionsHolder);
            m586H.append(", list=");
            m586H.append(this.f8410c);
            m586H.append(']');
            return m586H.toString();
        }
    }

    /* renamed from: c.a.i1$d */
    public static final class d extends C2961j.a {

        /* renamed from: d */
        public final /* synthetic */ C3068i1 f8411d;

        /* renamed from: e */
        public final /* synthetic */ Object f8412e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public d(C2961j c2961j, C2961j c2961j2, C3068i1 c3068i1, Object obj) {
            super(c2961j2);
            this.f8411d = c3068i1;
            this.f8412e = obj;
        }

        @Override // p379c.p380a.p381a.AbstractC2955d
        /* renamed from: c */
        public Object mo3417c(C2961j c2961j) {
            if (this.f8411d.m3576L() == this.f8412e) {
                return null;
            }
            return C2960i.f8110a;
        }
    }

    public C3068i1(boolean z) {
        this._state = z ? C3071j1.f8423g : C3071j1.f8422f;
        this._parentHandle = null;
    }

    /* renamed from: e0 */
    public static /* synthetic */ CancellationException m3569e0(C3068i1 c3068i1, Throwable th, String str, int i2, Object obj) {
        int i3 = i2 & 1;
        return c3068i1.m3587d0(th, null);
    }

    /* renamed from: A */
    public boolean mo3570A(@NotNull Throwable th) {
        if (th instanceof CancellationException) {
            return true;
        }
        return m3592w(th) && mo3557H();
    }

    /* renamed from: B */
    public final void m3571B(InterfaceC3115y0 interfaceC3115y0, Object obj) {
        InterfaceC3081n interfaceC3081n = (InterfaceC3081n) this._parentHandle;
        if (interfaceC3081n != null) {
            interfaceC3081n.dispose();
            this._parentHandle = C3083n1.f8433c;
        }
        C3117z c3117z = null;
        if (!(obj instanceof C3108w)) {
            obj = null;
        }
        C3108w c3108w = (C3108w) obj;
        Throwable th = c3108w != null ? c3108w.f8470b : null;
        if (interfaceC3115y0 instanceof AbstractC3065h1) {
            try {
                ((AbstractC3065h1) interfaceC3115y0).mo3514r(th);
                return;
            } catch (Throwable th2) {
                mo3503N(new C3117z("Exception in completion handler " + interfaceC3115y0 + " for " + this, th2));
                return;
            }
        }
        C3080m1 mo3560d = interfaceC3115y0.mo3560d();
        if (mo3560d != null) {
            Object m3428j = mo3560d.m3428j();
            Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
            for (C2961j c2961j = (C2961j) m3428j; !Intrinsics.areEqual(c2961j, mo3560d); c2961j = c2961j.m3429k()) {
                if (c2961j instanceof AbstractC3065h1) {
                    AbstractC3065h1 abstractC3065h1 = (AbstractC3065h1) c2961j;
                    try {
                        abstractC3065h1.mo3514r(th);
                    } catch (Throwable th3) {
                        if (c3117z != null) {
                            ExceptionsKt__ExceptionsKt.addSuppressed(c3117z, th3);
                        } else {
                            c3117z = new C3117z("Exception in completion handler " + abstractC3065h1 + " for " + this, th3);
                            Unit unit = Unit.INSTANCE;
                        }
                    }
                }
            }
            if (c3117z != null) {
                mo3503N(c3117z);
            }
        }
    }

    /* renamed from: F */
    public final Throwable m3572F(Object obj) {
        if (obj != null ? obj instanceof Throwable : true) {
            return obj != null ? (Throwable) obj : new C3056e1(mo3513z(), null, this);
        }
        Objects.requireNonNull(obj, "null cannot be cast to non-null type kotlinx.coroutines.ParentJob");
        return ((InterfaceC3089p1) obj).mo3574I();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: G */
    public final Object m3573G(c cVar, Object obj) {
        Throwable th = null;
        C3108w c3108w = (C3108w) (!(obj instanceof C3108w) ? null : obj);
        Throwable th2 = c3108w != null ? c3108w.f8470b : null;
        synchronized (cVar) {
            cVar.m3599e();
            List<Throwable> m3601g = cVar.m3601g(th2);
            if (!m3601g.isEmpty()) {
                Iterator<T> it = m3601g.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    Object next = it.next();
                    if (!(((Throwable) next) instanceof CancellationException)) {
                        th = next;
                        break;
                    }
                }
                th = th;
                if (th == null) {
                    th = m3601g.get(0);
                }
            } else if (cVar.m3599e()) {
                th = new C3056e1(mo3513z(), null, this);
            }
            if (th != null && m3601g.size() > 1) {
                Set newSetFromMap = Collections.newSetFromMap(new IdentityHashMap(m3601g.size()));
                for (Throwable th3 : m3601g) {
                    if (th3 != th && th3 != th && !(th3 instanceof CancellationException) && newSetFromMap.add(th3)) {
                        ExceptionsKt__ExceptionsKt.addSuppressed(th, th3);
                    }
                }
            }
        }
        if (th != null && th != th2) {
            obj = new C3108w(th, false, 2);
        }
        if (th != null) {
            if (m3594y(th) || mo3577M(th)) {
                Objects.requireNonNull(obj, "null cannot be cast to non-null type kotlinx.coroutines.CompletedExceptionally");
                C3108w.f8469a.compareAndSet((C3108w) obj, 0, 1);
            }
        }
        mo3505Y(obj);
        f8404c.compareAndSet(this, cVar, obj instanceof InterfaceC3115y0 ? new C3118z0((InterfaceC3115y0) obj) : obj);
        m3571B(cVar, obj);
        return obj;
    }

    /* renamed from: H */
    public boolean mo3557H() {
        return true;
    }

    @Override // p379c.p380a.InterfaceC3089p1
    @NotNull
    /* renamed from: I */
    public CancellationException mo3574I() {
        Throwable th;
        Object m3576L = m3576L();
        if (m3576L instanceof c) {
            th = (Throwable) ((c) m3576L)._rootCause;
        } else if (m3576L instanceof C3108w) {
            th = ((C3108w) m3576L).f8470b;
        } else {
            if (m3576L instanceof InterfaceC3115y0) {
                throw new IllegalStateException(C1499a.m636v("Cannot be cancelling child in this state: ", m3576L).toString());
            }
            th = null;
        }
        CancellationException cancellationException = (CancellationException) (th instanceof CancellationException ? th : null);
        if (cancellationException != null) {
            return cancellationException;
        }
        StringBuilder m586H = C1499a.m586H("Parent job is ");
        m586H.append(m3586c0(m3576L));
        return new C3056e1(m586H.toString(), th, this);
    }

    /* renamed from: J */
    public boolean mo3558J() {
        return this instanceof C3099t;
    }

    /* renamed from: K */
    public final C3080m1 m3575K(InterfaceC3115y0 interfaceC3115y0) {
        C3080m1 mo3560d = interfaceC3115y0.mo3560d();
        if (mo3560d != null) {
            return mo3560d;
        }
        if (interfaceC3115y0 instanceof C3088p0) {
            return new C3080m1();
        }
        if (interfaceC3115y0 instanceof AbstractC3065h1) {
            m3584a0((AbstractC3065h1) interfaceC3115y0);
            return null;
        }
        throw new IllegalStateException(("State should have list: " + interfaceC3115y0).toString());
    }

    @Nullable
    /* renamed from: L */
    public final Object m3576L() {
        while (true) {
            Object obj = this._state;
            if (!(obj instanceof AbstractC2966o)) {
                return obj;
            }
            ((AbstractC2966o) obj).mo3415a(this);
        }
    }

    /* renamed from: M */
    public boolean mo3577M(@NotNull Throwable th) {
        return false;
    }

    /* renamed from: N */
    public void mo3503N(@NotNull Throwable th) {
        throw th;
    }

    /* renamed from: O */
    public final void m3578O(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        if (interfaceC3053d1 == null) {
            this._parentHandle = C3083n1.f8433c;
            return;
        }
        interfaceC3053d1.start();
        InterfaceC3081n mo3550S = interfaceC3053d1.mo3550S(this);
        this._parentHandle = mo3550S;
        if (!(m3576L() instanceof InterfaceC3115y0)) {
            mo3550S.dispose();
            this._parentHandle = C3083n1.f8433c;
        }
    }

    /* renamed from: Q */
    public boolean mo3444Q() {
        return this instanceof C3054e;
    }

    /* renamed from: R */
    public final boolean m3579R(@Nullable Object obj) {
        Object m3588f0;
        do {
            m3588f0 = m3588f0(m3576L(), obj);
            if (m3588f0 == C3071j1.f8417a) {
                return false;
            }
            if (m3588f0 == C3071j1.f8418b) {
                return true;
            }
        } while (m3588f0 == C3071j1.f8419c);
        return true;
    }

    @Override // p379c.p380a.InterfaceC3053d1
    @NotNull
    /* renamed from: S */
    public final InterfaceC3081n mo3550S(@NotNull InterfaceC3087p interfaceC3087p) {
        InterfaceC3082n0 m2531y0 = C2354n.m2531y0(this, true, false, new C3084o(this, interfaceC3087p), 2, null);
        Objects.requireNonNull(m2531y0, "null cannot be cast to non-null type kotlinx.coroutines.ChildHandle");
        return (InterfaceC3081n) m2531y0;
    }

    @Nullable
    /* renamed from: T */
    public final Object m3580T(@Nullable Object obj) {
        Object m3588f0;
        do {
            m3588f0 = m3588f0(m3576L(), obj);
            if (m3588f0 == C3071j1.f8417a) {
                String str = "Job " + this + " is already complete or completing, but is being completed with " + obj;
                if (!(obj instanceof C3108w)) {
                    obj = null;
                }
                C3108w c3108w = (C3108w) obj;
                throw new IllegalStateException(str, c3108w != null ? c3108w.f8470b : null);
            }
        } while (m3588f0 == C3071j1.f8419c);
        return m3588f0;
    }

    /* renamed from: U */
    public final AbstractC3065h1<?> m3581U(Function1<? super Throwable, Unit> function1, boolean z) {
        if (z) {
            AbstractC3059f1 abstractC3059f1 = (AbstractC3059f1) (function1 instanceof AbstractC3059f1 ? function1 : null);
            return abstractC3059f1 != null ? abstractC3059f1 : new C3004b1(this, function1);
        }
        AbstractC3065h1<?> abstractC3065h1 = (AbstractC3065h1) (function1 instanceof AbstractC3065h1 ? function1 : null);
        return abstractC3065h1 != null ? abstractC3065h1 : new C3037c1(this, function1);
    }

    @NotNull
    /* renamed from: V */
    public String mo3504V() {
        return getClass().getSimpleName();
    }

    /* renamed from: W */
    public final C3084o m3582W(C2961j c2961j) {
        while (c2961j.mo3423n()) {
            c2961j = c2961j.m3430l();
        }
        while (true) {
            c2961j = c2961j.m3429k();
            if (!c2961j.mo3423n()) {
                if (c2961j instanceof C3084o) {
                    return (C3084o) c2961j;
                }
                if (c2961j instanceof C3080m1) {
                    return null;
                }
            }
        }
    }

    /* renamed from: X */
    public final void m3583X(C3080m1 c3080m1, Throwable th) {
        C3117z c3117z = null;
        Object m3428j = c3080m1.m3428j();
        Objects.requireNonNull(m3428j, "null cannot be cast to non-null type kotlinx.coroutines.internal.Node /* = kotlinx.coroutines.internal.LockFreeLinkedListNode */");
        for (C2961j c2961j = (C2961j) m3428j; !Intrinsics.areEqual(c2961j, c3080m1); c2961j = c2961j.m3429k()) {
            if (c2961j instanceof AbstractC3059f1) {
                AbstractC3065h1 abstractC3065h1 = (AbstractC3065h1) c2961j;
                try {
                    abstractC3065h1.mo3514r(th);
                } catch (Throwable th2) {
                    if (c3117z != null) {
                        ExceptionsKt__ExceptionsKt.addSuppressed(c3117z, th2);
                    } else {
                        c3117z = new C3117z("Exception in completion handler " + abstractC3065h1 + " for " + this, th2);
                        Unit unit = Unit.INSTANCE;
                    }
                }
            }
        }
        if (c3117z != null) {
            mo3503N(c3117z);
        }
        m3594y(th);
    }

    /* renamed from: Y */
    public void mo3505Y(@Nullable Object obj) {
    }

    /* renamed from: Z */
    public void mo3506Z() {
    }

    /* renamed from: a0 */
    public final void m3584a0(AbstractC3065h1<?> abstractC3065h1) {
        C3080m1 c3080m1 = new C3080m1();
        C2961j.f8112e.lazySet(c3080m1, abstractC3065h1);
        C2961j.f8111c.lazySet(c3080m1, abstractC3065h1);
        while (true) {
            if (abstractC3065h1.m3428j() != abstractC3065h1) {
                break;
            } else if (C2961j.f8111c.compareAndSet(abstractC3065h1, abstractC3065h1, c3080m1)) {
                c3080m1.m3427i(abstractC3065h1);
                break;
            }
        }
        f8404c.compareAndSet(this, abstractC3065h1, abstractC3065h1.m3429k());
    }

    @Override // p379c.p380a.InterfaceC3053d1
    /* renamed from: b */
    public boolean mo3507b() {
        Object m3576L = m3576L();
        return (m3576L instanceof InterfaceC3115y0) && ((InterfaceC3115y0) m3576L).mo3559b();
    }

    /* renamed from: b0 */
    public final int m3585b0(Object obj) {
        if (obj instanceof C3088p0) {
            if (((C3088p0) obj).f8436c) {
                return 0;
            }
            if (!f8404c.compareAndSet(this, obj, C3071j1.f8423g)) {
                return -1;
            }
            mo3506Z();
            return 1;
        }
        if (!(obj instanceof C3112x0)) {
            return 0;
        }
        if (!f8404c.compareAndSet(this, obj, ((C3112x0) obj).f8475c)) {
            return -1;
        }
        mo3506Z();
        return 1;
    }

    /* renamed from: c0 */
    public final String m3586c0(Object obj) {
        if (!(obj instanceof c)) {
            return obj instanceof InterfaceC3115y0 ? ((InterfaceC3115y0) obj).mo3559b() ? "Active" : "New" : obj instanceof C3108w ? "Cancelled" : "Completed";
        }
        c cVar = (c) obj;
        return cVar.m3599e() ? "Cancelling" : cVar._isCompleting != 0 ? "Completing" : "Active";
    }

    @Override // p379c.p380a.InterfaceC3053d1
    /* renamed from: d */
    public void mo3551d(@Nullable CancellationException cancellationException) {
        if (cancellationException == null) {
            cancellationException = new C3056e1(mo3513z(), null, this);
        }
        m3593x(cancellationException);
    }

    @NotNull
    /* renamed from: d0 */
    public final CancellationException m3587d0(@NotNull Throwable th, @Nullable String str) {
        CancellationException cancellationException = (CancellationException) (!(th instanceof CancellationException) ? null : th);
        if (cancellationException == null) {
            if (str == null) {
                str = mo3513z();
            }
            cancellationException = new C3056e1(str, th, this);
        }
        return cancellationException;
    }

    /* renamed from: f0 */
    public final Object m3588f0(Object obj, Object obj2) {
        if (!(obj instanceof InterfaceC3115y0)) {
            return C3071j1.f8417a;
        }
        boolean z = true;
        if (((obj instanceof C3088p0) || (obj instanceof AbstractC3065h1)) && !(obj instanceof C3084o) && !(obj2 instanceof C3108w)) {
            InterfaceC3115y0 interfaceC3115y0 = (InterfaceC3115y0) obj;
            if (f8404c.compareAndSet(this, interfaceC3115y0, obj2 instanceof InterfaceC3115y0 ? new C3118z0((InterfaceC3115y0) obj2) : obj2)) {
                mo3505Y(obj2);
                m3571B(interfaceC3115y0, obj2);
            } else {
                z = false;
            }
            return z ? obj2 : C3071j1.f8419c;
        }
        InterfaceC3115y0 interfaceC3115y02 = (InterfaceC3115y0) obj;
        C3080m1 m3575K = m3575K(interfaceC3115y02);
        if (m3575K == null) {
            return C3071j1.f8419c;
        }
        C3084o c3084o = null;
        c cVar = (c) (!(interfaceC3115y02 instanceof c) ? null : interfaceC3115y02);
        if (cVar == null) {
            cVar = new c(m3575K, false, null);
        }
        synchronized (cVar) {
            if (cVar._isCompleting != 0) {
                return C3071j1.f8417a;
            }
            cVar._isCompleting = 1;
            if (cVar != interfaceC3115y02 && !f8404c.compareAndSet(this, interfaceC3115y02, cVar)) {
                return C3071j1.f8419c;
            }
            boolean m3599e = cVar.m3599e();
            C3108w c3108w = (C3108w) (!(obj2 instanceof C3108w) ? null : obj2);
            if (c3108w != null) {
                cVar.m3597a(c3108w.f8470b);
            }
            Throwable th = (Throwable) cVar._rootCause;
            if (!(true ^ m3599e)) {
                th = null;
            }
            Unit unit = Unit.INSTANCE;
            if (th != null) {
                m3583X(m3575K, th);
            }
            C3084o c3084o2 = (C3084o) (!(interfaceC3115y02 instanceof C3084o) ? null : interfaceC3115y02);
            if (c3084o2 != null) {
                c3084o = c3084o2;
            } else {
                C3080m1 mo3560d = interfaceC3115y02.mo3560d();
                if (mo3560d != null) {
                    c3084o = m3582W(mo3560d);
                }
            }
            return (c3084o == null || !m3589g0(cVar, c3084o, obj2)) ? m3573G(cVar, obj2) : C3071j1.f8418b;
        }
    }

    @Override // kotlin.coroutines.CoroutineContext.Element, kotlin.coroutines.CoroutineContext
    public <R> R fold(R r, @NotNull Function2<? super R, ? super CoroutineContext.Element, ? extends R> function2) {
        return (R) CoroutineContext.Element.DefaultImpls.fold(this, r, function2);
    }

    /* renamed from: g0 */
    public final boolean m3589g0(c cVar, C3084o c3084o, Object obj) {
        while (C2354n.m2531y0(c3084o.f8434h, false, false, new b(this, cVar, c3084o, obj), 1, null) == C3083n1.f8433c) {
            c3084o = m3582W(c3084o);
            if (c3084o == null) {
                return false;
            }
        }
        return true;
    }

    @Override // kotlin.coroutines.CoroutineContext.Element, kotlin.coroutines.CoroutineContext
    @Nullable
    public <E extends CoroutineContext.Element> E get(@NotNull CoroutineContext.Key<E> key) {
        return (E) CoroutineContext.Element.DefaultImpls.get(this, key);
    }

    @Override // kotlin.coroutines.CoroutineContext.Element
    @NotNull
    public final CoroutineContext.Key<?> getKey() {
        return InterfaceC3053d1.f8393b;
    }

    @Override // p379c.p380a.InterfaceC3053d1
    public final boolean isCancelled() {
        Object m3576L = m3576L();
        return (m3576L instanceof C3108w) || ((m3576L instanceof c) && ((c) m3576L).m3599e());
    }

    @Override // kotlin.coroutines.CoroutineContext.Element, kotlin.coroutines.CoroutineContext
    @NotNull
    public CoroutineContext minusKey(@NotNull CoroutineContext.Key<?> key) {
        return CoroutineContext.Element.DefaultImpls.minusKey(this, key);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v3, types: [c.a.x0] */
    @Override // p379c.p380a.InterfaceC3053d1
    @NotNull
    /* renamed from: o */
    public final InterfaceC3082n0 mo3552o(boolean z, boolean z2, @NotNull Function1<? super Throwable, Unit> function1) {
        Throwable th;
        AbstractC3065h1<?> abstractC3065h1 = null;
        while (true) {
            Object m3576L = m3576L();
            if (m3576L instanceof C3088p0) {
                C3088p0 c3088p0 = (C3088p0) m3576L;
                if (c3088p0.f8436c) {
                    if (abstractC3065h1 == null) {
                        abstractC3065h1 = m3581U(function1, z);
                    }
                    if (f8404c.compareAndSet(this, m3576L, abstractC3065h1)) {
                        return abstractC3065h1;
                    }
                } else {
                    C3080m1 c3080m1 = new C3080m1();
                    if (!c3088p0.f8436c) {
                        c3080m1 = new C3112x0(c3080m1);
                    }
                    f8404c.compareAndSet(this, c3088p0, c3080m1);
                }
            } else {
                if (!(m3576L instanceof InterfaceC3115y0)) {
                    if (z2) {
                        if (!(m3576L instanceof C3108w)) {
                            m3576L = null;
                        }
                        C3108w c3108w = (C3108w) m3576L;
                        function1.invoke(c3108w != null ? c3108w.f8470b : null);
                    }
                    return C3083n1.f8433c;
                }
                C3080m1 mo3560d = ((InterfaceC3115y0) m3576L).mo3560d();
                if (mo3560d == null) {
                    Objects.requireNonNull(m3576L, "null cannot be cast to non-null type kotlinx.coroutines.JobNode<*>");
                    m3584a0((AbstractC3065h1) m3576L);
                } else {
                    InterfaceC3082n0 interfaceC3082n0 = C3083n1.f8433c;
                    if (z && (m3576L instanceof c)) {
                        synchronized (m3576L) {
                            th = (Throwable) ((c) m3576L)._rootCause;
                            if (th == null || ((function1 instanceof C3084o) && ((c) m3576L)._isCompleting == 0)) {
                                if (abstractC3065h1 == null) {
                                    abstractC3065h1 = m3581U(function1, z);
                                }
                                if (m3591u(m3576L, mo3560d, abstractC3065h1)) {
                                    if (th == null) {
                                        return abstractC3065h1;
                                    }
                                    interfaceC3082n0 = abstractC3065h1;
                                }
                            }
                            Unit unit = Unit.INSTANCE;
                        }
                    } else {
                        th = null;
                    }
                    if (th != null) {
                        if (z2) {
                            function1.invoke(th);
                        }
                        return interfaceC3082n0;
                    }
                    if (abstractC3065h1 == null) {
                        abstractC3065h1 = m3581U(function1, z);
                    }
                    if (m3591u(m3576L, mo3560d, abstractC3065h1)) {
                        return abstractC3065h1;
                    }
                }
            }
        }
    }

    @Override // kotlin.coroutines.CoroutineContext
    @NotNull
    public CoroutineContext plus(@NotNull CoroutineContext coroutineContext) {
        return CoroutineContext.Element.DefaultImpls.plus(this, coroutineContext);
    }

    @Override // p379c.p380a.InterfaceC3053d1
    @NotNull
    /* renamed from: q */
    public final CancellationException mo3553q() {
        Object m3576L = m3576L();
        if (m3576L instanceof c) {
            Throwable th = (Throwable) ((c) m3576L)._rootCause;
            if (th != null) {
                return m3587d0(th, getClass().getSimpleName() + " is cancelling");
            }
            throw new IllegalStateException(("Job is still new or active: " + this).toString());
        }
        if (m3576L instanceof InterfaceC3115y0) {
            throw new IllegalStateException(("Job is still new or active: " + this).toString());
        }
        if (m3576L instanceof C3108w) {
            return m3569e0(this, ((C3108w) m3576L).f8470b, null, 1, null);
        }
        return new C3056e1(getClass().getSimpleName() + " has completed normally", null, this);
    }

    @Override // p379c.p380a.InterfaceC3053d1
    public final boolean start() {
        int m3585b0;
        do {
            m3585b0 = m3585b0(m3576L());
            if (m3585b0 == 0) {
                return false;
            }
        } while (m3585b0 != 1);
        return true;
    }

    @Override // p379c.p380a.InterfaceC3087p
    /* renamed from: t */
    public final void mo3590t(@NotNull InterfaceC3089p1 interfaceC3089p1) {
        m3592w(interfaceC3089p1);
    }

    @NotNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(mo3504V() + '{' + m3586c0(m3576L()) + '}');
        sb.append('@');
        sb.append(C2354n.m2495m0(this));
        return sb.toString();
    }

    /* renamed from: u */
    public final boolean m3591u(Object obj, C3080m1 c3080m1, AbstractC3065h1<?> abstractC3065h1) {
        int m3433q;
        d dVar = new d(abstractC3065h1, abstractC3065h1, this, obj);
        do {
            m3433q = c3080m1.m3430l().m3433q(abstractC3065h1, c3080m1, dVar);
            if (m3433q == 1) {
                return true;
            }
        } while (m3433q != 2);
        return false;
    }

    /* renamed from: v */
    public void mo3446v(@Nullable Object obj) {
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00b9 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x003e A[SYNTHETIC] */
    /* renamed from: w */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m3592w(@org.jetbrains.annotations.Nullable java.lang.Object r9) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.C3068i1.m3592w(java.lang.Object):boolean");
    }

    /* renamed from: x */
    public void m3593x(@NotNull Throwable th) {
        m3592w(th);
    }

    /* renamed from: y */
    public final boolean m3594y(Throwable th) {
        if (mo3444Q()) {
            return true;
        }
        boolean z = th instanceof CancellationException;
        InterfaceC3081n interfaceC3081n = (InterfaceC3081n) this._parentHandle;
        return (interfaceC3081n == null || interfaceC3081n == C3083n1.f8433c) ? z : interfaceC3081n.mo3622c(th) || z;
    }

    @NotNull
    /* renamed from: z */
    public String mo3513z() {
        return "Job was cancelled";
    }
}
