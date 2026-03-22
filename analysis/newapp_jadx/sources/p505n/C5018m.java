package p505n;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;

/* renamed from: n.m */
/* loaded from: classes3.dex */
public final class C5018m extends Lambda implements Function1<Throwable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC4983d f12835c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5018m(InterfaceC4983d interfaceC4983d) {
        super(1);
        this.f12835c = interfaceC4983d;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        this.f12835c.cancel();
        return Unit.INSTANCE;
    }
}
