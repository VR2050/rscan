package p379c.p380a;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;

/* renamed from: c.a.b0 */
/* loaded from: classes2.dex */
public final class C3003b0 extends Lambda implements Function1<CoroutineContext.Element, AbstractC3036c0> {

    /* renamed from: c */
    public static final C3003b0 f8192c = new C3003b0();

    public C3003b0() {
        super(1);
    }

    @Override // kotlin.jvm.functions.Function1
    public AbstractC3036c0 invoke(CoroutineContext.Element element) {
        CoroutineContext.Element element2 = element;
        if (!(element2 instanceof AbstractC3036c0)) {
            element2 = null;
        }
        return (AbstractC3036c0) element2;
    }
}
