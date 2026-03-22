package p379c.p380a.p381a;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: c.a.a.n */
/* loaded from: classes2.dex */
public final class C2965n extends Lambda implements Function1<Throwable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ Function1 f8128c;

    /* renamed from: e */
    public final /* synthetic */ Object f8129e;

    /* renamed from: f */
    public final /* synthetic */ CoroutineContext f8130f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2965n(Function1 function1, Object obj, CoroutineContext coroutineContext) {
        super(1);
        this.f8128c = function1;
        this.f8129e = obj;
        this.f8130f = coroutineContext;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        Function1 function1 = this.f8128c;
        Object obj = this.f8129e;
        CoroutineContext coroutineContext = this.f8130f;
        C2975x m2503p = C2354n.m2503p(function1, obj, null);
        if (m2503p != null) {
            C2354n.m2516t0(coroutineContext, m2503p);
        }
        return Unit.INSTANCE;
    }
}
