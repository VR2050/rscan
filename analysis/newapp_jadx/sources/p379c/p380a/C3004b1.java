package p379c.p380a;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: c.a.b1 */
/* loaded from: classes2.dex */
public final class C3004b1 extends AbstractC3059f1<InterfaceC3053d1> {

    /* renamed from: h */
    public static final AtomicIntegerFieldUpdater f8193h = AtomicIntegerFieldUpdater.newUpdater(C3004b1.class, "_invoked");
    public volatile int _invoked;

    /* renamed from: i */
    public final Function1<Throwable, Unit> f8194i;

    /* JADX WARN: Multi-variable type inference failed */
    public C3004b1(@NotNull InterfaceC3053d1 interfaceC3053d1, @NotNull Function1<? super Throwable, Unit> function1) {
        super(interfaceC3053d1);
        this.f8194i = function1;
        this._invoked = 0;
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(Throwable th) {
        mo3514r(th);
        return Unit.INSTANCE;
    }

    @Override // p379c.p380a.AbstractC3114y
    /* renamed from: r */
    public void mo3514r(@Nullable Throwable th) {
        if (f8193h.compareAndSet(this, 0, 1)) {
            this.f8194i.invoke(th);
        }
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("InvokeOnCancelling[");
        m586H.append(C3004b1.class.getSimpleName());
        m586H.append('@');
        m586H.append(C2354n.m2495m0(this));
        m586H.append(']');
        return m586H.toString();
    }
}
