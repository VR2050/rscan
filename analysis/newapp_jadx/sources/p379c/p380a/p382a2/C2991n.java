package p379c.p380a.p382a2;

import java.util.concurrent.CancellationException;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3056e1;
import p379c.p380a.C3068i1;

/* renamed from: c.a.a2.n */
/* loaded from: classes2.dex */
public class C2991n<E> implements InterfaceC2992o<E>, InterfaceC2983f {

    /* renamed from: g */
    @NotNull
    public final InterfaceC2983f<E> f8184g;

    public C2991n(@NotNull CoroutineContext coroutineContext, @NotNull InterfaceC2983f<E> interfaceC2983f) {
        super(coroutineContext, true);
        this.f8184g = interfaceC2983f;
    }

    /* renamed from: b */
    public boolean m3497b() {
        return super.mo3507b();
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: c */
    public boolean mo3457c() {
        return this.f8184g.mo3457c();
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: d */
    public final void mo3458d(CancellationException cancellationException) {
        if (cancellationException == null) {
            cancellationException = new C3056e1(mo3513z(), null, this);
        }
        m3501x(cancellationException);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: e */
    public Object mo3459e(Continuation continuation) {
        return this.f8184g.mo3459e(continuation);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    public InterfaceC2984g iterator() {
        return this.f8184g.iterator();
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    /* renamed from: j */
    public boolean mo3480j(Throwable th) {
        return this.f8184g.mo3480j(th);
    }

    /* renamed from: j0 */
    public void m3498j0(@NotNull Throwable th, boolean z) {
        if (this.f8184g.mo3480j(th) || z) {
            return;
        }
        C2354n.m2516t0(this.f8190e, th);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2992o
    /* renamed from: k */
    public InterfaceC2998u mo3499k() {
        return this;
    }

    /* renamed from: k0 */
    public void m3500k0(Object obj) {
        this.f8184g.mo3480j(null);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    /* renamed from: m */
    public void mo3482m(Function1 function1) {
        this.f8184g.mo3482m(function1);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: n */
    public Object mo3460n(Continuation continuation) {
        return this.f8184g.mo3460n(continuation);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    public boolean offer(Object obj) {
        return this.f8184g.offer(obj);
    }

    @Override // p379c.p380a.p382a2.InterfaceC2998u
    /* renamed from: p */
    public Object mo3484p(Object obj, Continuation continuation) {
        return this.f8184g.mo3484p(obj, continuation);
    }

    /* renamed from: x */
    public void m3501x(Throwable th) {
        CancellationException m3569e0 = C3068i1.m3569e0(this, th, null, 1, null);
        this.f8184g.mo3458d(m3569e0);
        m3592w(m3569e0);
    }
}
