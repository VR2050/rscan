package p379c.p380a.p381a;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.jvm.internal.CoroutineStackFrame;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.AbstractC3076l0;
import p379c.p380a.AbstractC3091q0;
import p379c.p380a.C3107v1;
import p379c.p380a.C3111x;

/* renamed from: c.a.a.f */
/* loaded from: classes2.dex */
public final class C2957f<T> extends AbstractC3076l0<T> implements CoroutineStackFrame, Continuation<T> {

    /* renamed from: g */
    public static final AtomicReferenceFieldUpdater f8102g = AtomicReferenceFieldUpdater.newUpdater(C2957f.class, Object.class, "_reusableCancellableContinuation");
    public volatile Object _reusableCancellableContinuation;

    /* renamed from: h */
    @JvmField
    @Nullable
    public Object f8103h;

    /* renamed from: i */
    @Nullable
    public final CoroutineStackFrame f8104i;

    /* renamed from: j */
    @JvmField
    @NotNull
    public final Object f8105j;

    /* renamed from: k */
    @JvmField
    @NotNull
    public final AbstractC3036c0 f8106k;

    /* renamed from: l */
    @JvmField
    @NotNull
    public final Continuation<T> f8107l;

    /* JADX WARN: Multi-variable type inference failed */
    public C2957f(@NotNull AbstractC3036c0 abstractC3036c0, @NotNull Continuation<? super T> continuation) {
        super(-1);
        this.f8106k = abstractC3036c0;
        this.f8107l = continuation;
        this.f8103h = C2958g.f8108a;
        this.f8104i = continuation instanceof CoroutineStackFrame ? continuation : (Continuation<? super T>) null;
        this.f8105j = C2952a.m3413b(get$context());
        this._reusableCancellableContinuation = null;
    }

    @Override // p379c.p380a.AbstractC3076l0
    /* renamed from: b */
    public void mo3418b(@Nullable Object obj, @NotNull Throwable th) {
        if (obj instanceof C3111x) {
            ((C3111x) obj).f8474b.invoke(th);
        }
    }

    @Override // p379c.p380a.AbstractC3076l0
    @NotNull
    /* renamed from: c */
    public Continuation<T> mo3419c() {
        return this;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public CoroutineStackFrame getCallerFrame() {
        return this.f8104i;
    }

    @Override // kotlin.coroutines.Continuation
    @NotNull
    /* renamed from: getContext */
    public CoroutineContext get$context() {
        return this.f8107l.get$context();
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // p379c.p380a.AbstractC3076l0
    @Nullable
    /* renamed from: k */
    public Object mo3420k() {
        Object obj = this.f8103h;
        this.f8103h = C2958g.f8108a;
        return obj;
    }

    @Override // kotlin.coroutines.Continuation
    public void resumeWith(@NotNull Object obj) {
        CoroutineContext coroutineContext = this.f8107l.get$context();
        Object m2448Y1 = C2354n.m2448Y1(obj, null);
        if (this.f8106k.isDispatchNeeded(coroutineContext)) {
            this.f8103h = m2448Y1;
            this.f8428f = 0;
            this.f8106k.dispatch(coroutineContext, this);
            return;
        }
        C3107v1 c3107v1 = C3107v1.f8468b;
        AbstractC3091q0 m3642a = C3107v1.m3642a();
        if (m3642a.m3630Y()) {
            this.f8103h = m2448Y1;
            this.f8428f = 0;
            m3642a.m3628W(this);
            return;
        }
        m3642a.m3629X(true);
        try {
            CoroutineContext coroutineContext2 = get$context();
            Object m3414c = C2952a.m3414c(coroutineContext2, this.f8105j);
            try {
                this.f8107l.resumeWith(obj);
                Unit unit = Unit.INSTANCE;
                while (m3642a.m3632a0()) {
                }
            } finally {
                C2952a.m3412a(coroutineContext2, m3414c);
            }
        } finally {
            try {
            } finally {
            }
        }
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("DispatchedContinuation[");
        m586H.append(this.f8106k);
        m586H.append(", ");
        m586H.append(C2354n.m2436U1(this.f8107l));
        m586H.append(']');
        return m586H.toString();
    }
}
