package p379c.p380a.p382a2;

import kotlin.BuilderInference;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C2976a0;
import p379c.p380a.InterfaceC3055e0;

/* renamed from: c.a.a2.m */
/* loaded from: classes2.dex */
public final class C2990m {
    /* JADX WARN: Incorrect types in method signature: <E:Ljava/lang/Object;>(Lc/a/e0;Lkotlin/coroutines/CoroutineContext;ILc/a/a2/e;Ljava/lang/Object;Lkotlin/jvm/functions/Function1<-Ljava/lang/Throwable;Lkotlin/Unit;>;Lkotlin/jvm/functions/Function2<-Lc/a/a2/o<-TE;>;-Lkotlin/coroutines/Continuation<-Lkotlin/Unit;>;+Ljava/lang/Object;>;)Lc/a/a2/q<TE;>; */
    @NotNull
    /* renamed from: a */
    public static final InterfaceC2994q m3496a(@NotNull InterfaceC3055e0 interfaceC3055e0, @NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e, @NotNull int i3, @Nullable Function1 function1, @BuilderInference @NotNull Function2 function2) {
        C2991n c2991n = new C2991n(C2976a0.m3455a(interfaceC3055e0, coroutineContext), C2354n.m2452a(i2, enumC2982e, null, 4));
        if (function1 != null) {
            c2991n.mo3552o(false, true, function1);
        }
        c2991n.m3512m0(i3, c2991n, function2);
        return c2991n;
    }
}
