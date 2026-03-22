package com.jbzd.media.movecartoons.p396ui.share;

import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\u0006\u0010\u0001\u001a\u00020\u0000H\u008a@¢\u0006\u0004\b\u0004\u0010\u0005"}, m5311d2 = {"", "it", "Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "<anonymous>", "(Ljava/lang/Object;)Lc/a/b2/b;"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.share.BindCodeViewModel$bindParent$1", m5320f = "BindCodeViewModel.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class BindCodeViewModel$bindParent$1 extends SuspendLambda implements Function2<Object, Continuation<? super InterfaceC3006b<? extends UserInfoBean>>, Object> {
    public final /* synthetic */ C0944a $repository;
    public int label;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BindCodeViewModel$bindParent$1(C0944a c0944a, Continuation<? super BindCodeViewModel$bindParent$1> continuation) {
        super(2, continuation);
        this.$repository = c0944a;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new BindCodeViewModel$bindParent$1(this.$repository, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull Object obj, @Nullable Continuation<? super InterfaceC3006b<? extends UserInfoBean>> continuation) {
        return ((BindCodeViewModel$bindParent$1) create(obj, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        ResultKt.throwOnFailure(obj);
        return this.$repository.m288b();
    }
}
