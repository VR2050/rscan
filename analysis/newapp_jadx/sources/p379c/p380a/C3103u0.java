package p379c.p380a;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;

/* renamed from: c.a.u0 */
/* loaded from: classes2.dex */
public final class C3103u0 extends Lambda implements Function1<CoroutineContext.Element, AbstractC3106v0> {

    /* renamed from: c */
    public static final C3103u0 f8461c = new C3103u0();

    public C3103u0() {
        super(1);
    }

    @Override // kotlin.jvm.functions.Function1
    public AbstractC3106v0 invoke(CoroutineContext.Element element) {
        CoroutineContext.Element element2 = element;
        if (!(element2 instanceof AbstractC3106v0)) {
            element2 = null;
        }
        return (AbstractC3106v0) element2;
    }
}
