package p379c.p380a.p383b2.p384n;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.SuspendFunction;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.FunctionReferenceImpl;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.TypeIntrinsics;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.m */
/* loaded from: classes2.dex */
public final class C3030m {

    /* renamed from: a */
    public static final Function3<InterfaceC3007c<Object>, Object, Continuation<? super Unit>, Object> f8331a = (Function3) TypeIntrinsics.beforeCheckcastToFunctionOfArity(new a(), 3);

    /* renamed from: c.a.b2.n.m$a */
    public static final /* synthetic */ class a extends FunctionReferenceImpl implements Function3<InterfaceC3007c<? super Object>, Object, Continuation<? super Unit>, Object>, SuspendFunction {
        public a() {
            super(3, InterfaceC3007c.class, "emit", "emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", 0);
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(InterfaceC3007c<? super Object> interfaceC3007c, Object obj, Continuation<? super Unit> continuation) {
            InlineMarker.mark(0);
            Object emit = interfaceC3007c.emit(obj, continuation);
            InlineMarker.mark(2);
            InlineMarker.mark(1);
            return emit;
        }
    }
}
