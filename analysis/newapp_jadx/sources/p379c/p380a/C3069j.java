package p379c.p380a;

import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.PublishedApi;
import kotlin.Result;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.CoroutineStackFrame;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2957f;
import p379c.p380a.p381a.C2958g;
import p379c.p380a.p381a.C2970s;

@PublishedApi
/* renamed from: c.a.j */
/* loaded from: classes2.dex */
public class C3069j<T> extends AbstractC3076l0<T> implements InterfaceC3066i<T>, CoroutineStackFrame {

    /* renamed from: g */
    public static final AtomicIntegerFieldUpdater f8413g = AtomicIntegerFieldUpdater.newUpdater(C3069j.class, "_decision");

    /* renamed from: h */
    public static final AtomicReferenceFieldUpdater f8414h = AtomicReferenceFieldUpdater.newUpdater(C3069j.class, Object.class, "_state");
    public volatile int _decision;
    public volatile Object _parentHandle;
    public volatile Object _state;

    /* renamed from: i */
    @NotNull
    public final CoroutineContext f8415i;

    /* renamed from: j */
    @NotNull
    public final Continuation<T> f8416j;

    /* JADX WARN: Multi-variable type inference failed */
    public C3069j(@NotNull Continuation<? super T> continuation, int i2) {
        super(i2);
        this.f8416j = continuation;
        this.f8415i = continuation.get$context();
        this._decision = 0;
        this._state = C3035c.f8343c;
        this._parentHandle = null;
    }

    /* renamed from: A */
    public final void m3602A() {
        InterfaceC3053d1 interfaceC3053d1;
        boolean z = !(this._state instanceof InterfaceC3086o1);
        if (this.f8428f == 2) {
            Continuation<T> continuation = this.f8416j;
            Throwable th = null;
            if (!(continuation instanceof C2957f)) {
                continuation = null;
            }
            C2957f c2957f = (C2957f) continuation;
            if (c2957f != null) {
                while (true) {
                    Object obj = c2957f._reusableCancellableContinuation;
                    C2970s c2970s = C2958g.f8109b;
                    if (obj == c2970s) {
                        if (C2957f.f8102g.compareAndSet(c2957f, c2970s, this)) {
                            break;
                        }
                    } else if (obj != null) {
                        if (!(obj instanceof Throwable)) {
                            throw new IllegalStateException(C1499a.m636v("Inconsistent state ", obj).toString());
                        }
                        if (!C2957f.f8102g.compareAndSet(c2957f, obj, null)) {
                            throw new IllegalArgumentException("Failed requirement.".toString());
                        }
                        th = (Throwable) obj;
                    }
                }
                if (th != null) {
                    if (!z) {
                        mo3566l(th);
                    }
                    z = true;
                }
            }
        }
        if (z || ((InterfaceC3082n0) this._parentHandle) != null || (interfaceC3053d1 = (InterfaceC3053d1) this.f8416j.get$context().get(InterfaceC3053d1.f8393b)) == null) {
            return;
        }
        InterfaceC3082n0 m2531y0 = C2354n.m2531y0(interfaceC3053d1, true, false, new C3078m(interfaceC3053d1, this), 2, null);
        this._parentHandle = m2531y0;
        if (!(true ^ (this._state instanceof InterfaceC3086o1)) || m3613v()) {
            return;
        }
        m2531y0.dispose();
        this._parentHandle = C3083n1.f8433c;
    }

    /* renamed from: B */
    public final C2970s m3603B(Object obj, Object obj2, Function1<? super Throwable, Unit> function1) {
        Object obj3;
        do {
            obj3 = this._state;
            if (!(obj3 instanceof InterfaceC3086o1)) {
                if ((obj3 instanceof C3105v) && obj2 != null && ((C3105v) obj3).f8465d == obj2) {
                    return C3072k.f8424a;
                }
                return null;
            }
        } while (!f8414h.compareAndSet(this, obj3, m3616z((InterfaceC3086o1) obj3, obj, this.f8428f, function1, obj2)));
        m3610q();
        return C3072k.f8424a;
    }

    @Override // p379c.p380a.InterfaceC3066i
    @Nullable
    /* renamed from: a */
    public Object mo3561a(T t, @Nullable Object obj) {
        return m3603B(t, obj, null);
    }

    @Override // p379c.p380a.AbstractC3076l0
    /* renamed from: b */
    public void mo3418b(@Nullable Object obj, @NotNull Throwable th) {
        while (true) {
            Object obj2 = this._state;
            if (obj2 instanceof InterfaceC3086o1) {
                throw new IllegalStateException("Not completed".toString());
            }
            if (obj2 instanceof C3108w) {
                return;
            }
            if (obj2 instanceof C3105v) {
                C3105v c3105v = (C3105v) obj2;
                if (!(!(c3105v.f8466e != null))) {
                    throw new IllegalStateException("Must be called at most once".toString());
                }
                if (f8414h.compareAndSet(this, obj2, C3105v.m3641a(c3105v, null, null, null, null, th, 15))) {
                    AbstractC3060g abstractC3060g = c3105v.f8463b;
                    if (abstractC3060g != null) {
                        m3607n(abstractC3060g, th);
                    }
                    Function1<Throwable, Unit> function1 = c3105v.f8464c;
                    if (function1 != null) {
                        m3608o(function1, th);
                        return;
                    }
                    return;
                }
            } else if (f8414h.compareAndSet(this, obj2, new C3105v(obj2, null, null, null, th, 14))) {
                return;
            }
        }
    }

    @Override // p379c.p380a.AbstractC3076l0
    @NotNull
    /* renamed from: c */
    public final Continuation<T> mo3419c() {
        return this.f8416j;
    }

    @Override // p379c.p380a.AbstractC3076l0
    @Nullable
    /* renamed from: d */
    public Throwable mo3604d(@Nullable Object obj) {
        Throwable mo3604d = super.mo3604d(obj);
        if (mo3604d != null) {
            return mo3604d;
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p379c.p380a.AbstractC3076l0
    /* renamed from: e */
    public <T> T mo3605e(@Nullable Object obj) {
        return obj instanceof C3105v ? (T) ((C3105v) obj).f8462a : obj;
    }

    @Override // p379c.p380a.InterfaceC3066i
    /* renamed from: f */
    public void mo3562f(@NotNull Function1<? super Throwable, Unit> function1) {
        AbstractC3060g c2977a1 = function1 instanceof AbstractC3060g ? (AbstractC3060g) function1 : new C2977a1(function1);
        while (true) {
            Object obj = this._state;
            if (!(obj instanceof C3035c)) {
                if (obj instanceof AbstractC3060g) {
                    m3614w(function1, obj);
                    throw null;
                }
                boolean z = obj instanceof C3108w;
                if (z) {
                    C3108w c3108w = (C3108w) obj;
                    Objects.requireNonNull(c3108w);
                    if (!C3108w.f8469a.compareAndSet(c3108w, 0, 1)) {
                        m3614w(function1, obj);
                        throw null;
                    }
                    if (obj instanceof C3075l) {
                        if (!z) {
                            obj = null;
                        }
                        C3108w c3108w2 = (C3108w) obj;
                        m3606m(function1, c3108w2 != null ? c3108w2.f8470b : null);
                        return;
                    }
                    return;
                }
                if (obj instanceof C3105v) {
                    C3105v c3105v = (C3105v) obj;
                    if (c3105v.f8463b != null) {
                        m3614w(function1, obj);
                        throw null;
                    }
                    if (c2977a1 instanceof AbstractC3051d) {
                        return;
                    }
                    Throwable th = c3105v.f8466e;
                    if (th != null) {
                        m3606m(function1, th);
                        return;
                    } else {
                        if (f8414h.compareAndSet(this, obj, C3105v.m3641a(c3105v, null, c2977a1, null, null, null, 29))) {
                            return;
                        }
                    }
                } else {
                    if (c2977a1 instanceof AbstractC3051d) {
                        return;
                    }
                    if (f8414h.compareAndSet(this, obj, new C3105v(obj, c2977a1, null, null, null, 28))) {
                        return;
                    }
                }
            } else if (f8414h.compareAndSet(this, obj, c2977a1)) {
                return;
            }
        }
    }

    @Override // p379c.p380a.InterfaceC3066i
    @Nullable
    /* renamed from: g */
    public Object mo3563g(@NotNull Throwable th) {
        return m3603B(new C3108w(th, false, 2), null, null);
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public CoroutineStackFrame getCallerFrame() {
        Continuation<T> continuation = this.f8416j;
        if (!(continuation instanceof CoroutineStackFrame)) {
            continuation = null;
        }
        return (CoroutineStackFrame) continuation;
    }

    @Override // kotlin.coroutines.Continuation
    @NotNull
    /* renamed from: getContext */
    public CoroutineContext get$context() {
        return this.f8415i;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // p379c.p380a.InterfaceC3066i
    @Nullable
    /* renamed from: h */
    public Object mo3564h(T t, @Nullable Object obj, @Nullable Function1<? super Throwable, Unit> function1) {
        return m3603B(t, null, function1);
    }

    @Override // p379c.p380a.InterfaceC3066i
    /* renamed from: i */
    public void mo3565i(@NotNull AbstractC3036c0 abstractC3036c0, T t) {
        Continuation<T> continuation = this.f8416j;
        if (!(continuation instanceof C2957f)) {
            continuation = null;
        }
        C2957f c2957f = (C2957f) continuation;
        m3615y(t, (c2957f != null ? c2957f.f8106k : null) == abstractC3036c0 ? 4 : this.f8428f, null);
    }

    @Override // p379c.p380a.AbstractC3076l0
    @Nullable
    /* renamed from: k */
    public Object mo3420k() {
        return this._state;
    }

    @Override // p379c.p380a.InterfaceC3066i
    /* renamed from: l */
    public boolean mo3566l(@Nullable Throwable th) {
        Object obj;
        boolean z;
        do {
            obj = this._state;
            if (!(obj instanceof InterfaceC3086o1)) {
                return false;
            }
            z = obj instanceof AbstractC3060g;
        } while (!f8414h.compareAndSet(this, obj, new C3075l(this, th, z)));
        if (!z) {
            obj = null;
        }
        AbstractC3060g abstractC3060g = (AbstractC3060g) obj;
        if (abstractC3060g != null) {
            m3607n(abstractC3060g, th);
        }
        m3610q();
        m3611s(this.f8428f);
        return true;
    }

    /* renamed from: m */
    public final void m3606m(Function1<? super Throwable, Unit> function1, Throwable th) {
        try {
            function1.invoke(th);
        } catch (Throwable th2) {
            C2354n.m2516t0(this.f8415i, new C3117z("Exception in invokeOnCancellation handler for " + this, th2));
        }
    }

    /* renamed from: n */
    public final void m3607n(@NotNull AbstractC3060g abstractC3060g, @Nullable Throwable th) {
        try {
            abstractC3060g.mo3456a(th);
        } catch (Throwable th2) {
            C2354n.m2516t0(this.f8415i, new C3117z("Exception in invokeOnCancellation handler for " + this, th2));
        }
    }

    /* renamed from: o */
    public final void m3608o(@NotNull Function1<? super Throwable, Unit> function1, @NotNull Throwable th) {
        try {
            function1.invoke(th);
        } catch (Throwable th2) {
            C2354n.m2516t0(this.f8415i, new C3117z("Exception in resume onCancellation handler for " + this, th2));
        }
    }

    /* renamed from: p */
    public final void m3609p() {
        InterfaceC3082n0 interfaceC3082n0 = (InterfaceC3082n0) this._parentHandle;
        if (interfaceC3082n0 != null) {
            interfaceC3082n0.dispose();
        }
        this._parentHandle = C3083n1.f8433c;
    }

    /* renamed from: q */
    public final void m3610q() {
        if (m3613v()) {
            return;
        }
        m3609p();
    }

    @Override // p379c.p380a.InterfaceC3066i
    /* renamed from: r */
    public void mo3567r(@NotNull Object obj) {
        m3611s(this.f8428f);
    }

    @Override // kotlin.coroutines.Continuation
    public void resumeWith(@NotNull Object obj) {
        Throwable m6058exceptionOrNullimpl = Result.m6058exceptionOrNullimpl(obj);
        if (m6058exceptionOrNullimpl != null) {
            obj = new C3108w(m6058exceptionOrNullimpl, false, 2);
        }
        m3615y(obj, this.f8428f, null);
    }

    /* JADX WARN: Finally extract failed */
    /* renamed from: s */
    public final void m3611s(int i2) {
        boolean z;
        while (true) {
            int i3 = this._decision;
            if (i3 != 0) {
                if (i3 != 1) {
                    throw new IllegalStateException("Already resumed".toString());
                }
                z = false;
            } else if (f8413g.compareAndSet(this, 0, 2)) {
                z = true;
                break;
            }
        }
        if (z) {
            return;
        }
        Continuation<T> mo3419c = mo3419c();
        boolean z2 = i2 == 4;
        if (z2 || !(mo3419c instanceof C2957f) || C2354n.m2402J0(i2) != C2354n.m2402J0(this.f8428f)) {
            C2354n.m2517t1(this, mo3419c, z2);
            return;
        }
        AbstractC3036c0 abstractC3036c0 = ((C2957f) mo3419c).f8106k;
        CoroutineContext coroutineContext = mo3419c.get$context();
        if (abstractC3036c0.isDispatchNeeded(coroutineContext)) {
            abstractC3036c0.dispatch(coroutineContext, this);
            return;
        }
        C3107v1 c3107v1 = C3107v1.f8468b;
        AbstractC3091q0 m3642a = C3107v1.m3642a();
        if (m3642a.m3630Y()) {
            m3642a.m3628W(this);
            return;
        }
        m3642a.m3629X(true);
        try {
            C2354n.m2517t1(this, mo3419c(), true);
            do {
            } while (m3642a.m3632a0());
        } catch (Throwable th) {
            try {
                m3619j(th, null);
            } finally {
                m3642a.m3626U(true);
            }
        }
    }

    @NotNull
    /* renamed from: t */
    public Throwable mo3595t(@NotNull InterfaceC3053d1 interfaceC3053d1) {
        return interfaceC3053d1.mo3553q();
    }

    @NotNull
    public String toString() {
        return mo3596x() + '(' + C2354n.m2436U1(this.f8416j) + "){" + this._state + "}@" + C2354n.m2495m0(this);
    }

    @PublishedApi
    @Nullable
    /* renamed from: u */
    public final Object m3612u() {
        boolean z;
        InterfaceC3053d1 interfaceC3053d1;
        m3602A();
        while (true) {
            int i2 = this._decision;
            z = false;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new IllegalStateException("Already suspended".toString());
                }
            } else if (f8413g.compareAndSet(this, 0, 1)) {
                z = true;
                break;
            }
        }
        if (z) {
            return IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        }
        Object obj = this._state;
        if (obj instanceof C3108w) {
            throw ((C3108w) obj).f8470b;
        }
        if (!C2354n.m2402J0(this.f8428f) || (interfaceC3053d1 = (InterfaceC3053d1) this.f8415i.get(InterfaceC3053d1.f8393b)) == null || interfaceC3053d1.mo3507b()) {
            return mo3605e(obj);
        }
        CancellationException mo3553q = interfaceC3053d1.mo3553q();
        mo3418b(obj, mo3553q);
        throw mo3553q;
    }

    /* renamed from: v */
    public final boolean m3613v() {
        Continuation<T> continuation = this.f8416j;
        if (!(continuation instanceof C2957f)) {
            return false;
        }
        Object obj = ((C2957f) continuation)._reusableCancellableContinuation;
        return obj != null && (!(obj instanceof C3069j) || obj == this);
    }

    /* renamed from: w */
    public final void m3614w(Function1<? super Throwable, Unit> function1, Object obj) {
        throw new IllegalStateException(("It's prohibited to register multiple handlers, tried to register " + function1 + ", already has " + obj).toString());
    }

    @NotNull
    /* renamed from: x */
    public String mo3596x() {
        return "CancellableContinuation";
    }

    /* renamed from: y */
    public final void m3615y(Object obj, int i2, Function1<? super Throwable, Unit> function1) {
        Object obj2;
        do {
            obj2 = this._state;
            if (!(obj2 instanceof InterfaceC3086o1)) {
                if (obj2 instanceof C3075l) {
                    C3075l c3075l = (C3075l) obj2;
                    Objects.requireNonNull(c3075l);
                    if (C3075l.f8427c.compareAndSet(c3075l, 0, 1)) {
                        if (function1 != null) {
                            m3608o(function1, c3075l.f8470b);
                            return;
                        }
                        return;
                    }
                }
                throw new IllegalStateException(C1499a.m636v("Already resumed, but proposed with update ", obj).toString());
            }
        } while (!f8414h.compareAndSet(this, obj2, m3616z((InterfaceC3086o1) obj2, obj, i2, function1, null)));
        m3610q();
        m3611s(i2);
    }

    /* renamed from: z */
    public final Object m3616z(InterfaceC3086o1 interfaceC3086o1, Object obj, int i2, Function1<? super Throwable, Unit> function1, Object obj2) {
        if (obj instanceof C3108w) {
            return obj;
        }
        if (!C2354n.m2402J0(i2) && obj2 == null) {
            return obj;
        }
        if (function1 == null && ((!(interfaceC3086o1 instanceof AbstractC3060g) || (interfaceC3086o1 instanceof AbstractC3051d)) && obj2 == null)) {
            return obj;
        }
        if (!(interfaceC3086o1 instanceof AbstractC3060g)) {
            interfaceC3086o1 = null;
        }
        return new C3105v(obj, (AbstractC3060g) interfaceC3086o1, function1, obj2, null, 16);
    }
}
