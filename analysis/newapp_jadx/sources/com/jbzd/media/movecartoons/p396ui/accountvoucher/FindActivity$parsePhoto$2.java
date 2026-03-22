package com.jbzd.media.movecartoons.p396ui.accountvoucher;

import com.jbzd.media.movecartoons.bean.TokenBean;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00040\u00032\u000e\u0010\u0002\u001a\n \u0001*\u0004\u0018\u00010\u00000\u0000H\u008a@¢\u0006\u0004\b\u0005\u0010\u0006"}, m5311d2 = {"", "kotlin.jvm.PlatformType", "it", "Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/TokenBean;", "<anonymous>", "(Ljava/lang/String;)Lc/a/b2/b;"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$parsePhoto$2", m5320f = "FindActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class FindActivity$parsePhoto$2 extends SuspendLambda implements Function2<String, Continuation<? super InterfaceC3006b<? extends TokenBean>>, Object> {
    public /* synthetic */ Object L$0;
    public int label;

    public FindActivity$parsePhoto$2(Continuation<? super FindActivity$parsePhoto$2> continuation) {
        super(2, continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        FindActivity$parsePhoto$2 findActivity$parsePhoto$2 = new FindActivity$parsePhoto$2(continuation);
        findActivity$parsePhoto$2.L$0 = obj;
        return findActivity$parsePhoto$2;
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(String str, @Nullable Continuation<? super InterfaceC3006b<? extends TokenBean>> continuation) {
        return ((FindActivity$parsePhoto$2) create(str, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        ResultKt.throwOnFailure(obj);
        String code = (String) this.L$0;
        Lazy lazy = LazyKt__LazyJVMKt.lazy(C0944a.a.f472c);
        Intrinsics.checkNotNullExpressionValue(code, "it");
        Intrinsics.checkNotNullParameter(code, "code");
        return ((InterfaceC0921e) lazy.getValue()).m252k(code);
    }
}
