package p005b.p303q.p304a.p305a.p306a.p307a;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;
import p379c.p380a.InterfaceC3096s;
import p505n.InterfaceC4983d;

/* renamed from: b.q.a.a.a.a.a */
/* loaded from: classes2.dex */
public final class C2718a extends Lambda implements Function1<Throwable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC3096s f7389c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC4983d f7390e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2718a(InterfaceC3096s interfaceC3096s, InterfaceC4983d interfaceC4983d) {
        super(1);
        this.f7389c = interfaceC3096s;
        this.f7390e = interfaceC4983d;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        if (this.f7389c.isCancelled()) {
            this.f7390e.cancel();
        }
        return Unit.INSTANCE;
    }
}
