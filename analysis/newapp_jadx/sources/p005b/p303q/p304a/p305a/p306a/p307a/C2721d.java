package p005b.p303q.p304a.p305a.p306a.p307a;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;
import p379c.p380a.InterfaceC3096s;
import p505n.InterfaceC4983d;

/* renamed from: b.q.a.a.a.a.d */
/* loaded from: classes2.dex */
public final class C2721d extends Lambda implements Function1<Throwable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC3096s f7394c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC4983d f7395e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2721d(InterfaceC3096s interfaceC3096s, InterfaceC4983d interfaceC4983d) {
        super(1);
        this.f7394c = interfaceC3096s;
        this.f7395e = interfaceC4983d;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        if (this.f7394c.isCancelled()) {
            this.f7395e.cancel();
        }
        return Unit.INSTANCE;
    }
}
