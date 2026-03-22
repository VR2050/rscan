package com.jbzd.media.movecartoons.p396ui.settings;

import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\u0006\u0010\u0001\u001a\u00020\u0000H\u008a@¢\u0006\u0004\b\u0004\u0010\u0005"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/TokenBean;", "it", "Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "<anonymous>", "(Lcom/jbzd/media/movecartoons/bean/TokenBean;)Lc/a/b2/b;"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.settings.SignViewModel$refreshAccount$1", m5320f = "SignViewModel.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class SignViewModel$refreshAccount$1 extends SuspendLambda implements Function2<TokenBean, Continuation<? super InterfaceC3006b<? extends UserInfoBean>>, Object> {
    public /* synthetic */ Object L$0;
    public int label;
    public final /* synthetic */ SignViewModel this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SignViewModel$refreshAccount$1(SignViewModel signViewModel, Continuation<? super SignViewModel$refreshAccount$1> continuation) {
        super(2, continuation);
        this.this$0 = signViewModel;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        SignViewModel$refreshAccount$1 signViewModel$refreshAccount$1 = new SignViewModel$refreshAccount$1(this.this$0, continuation);
        signViewModel$refreshAccount$1.L$0 = obj;
        return signViewModel$refreshAccount$1;
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull TokenBean tokenBean, @Nullable Continuation<? super InterfaceC3006b<? extends UserInfoBean>> continuation) {
        return ((SignViewModel$refreshAccount$1) create(tokenBean, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        C0944a repository;
        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        ResultKt.throwOnFailure(obj);
        TokenBean tokenBean = (TokenBean) this.L$0;
        MyApp myApp = MyApp.f9891f;
        MyApp.m4188i(tokenBean);
        repository = this.this$0.getRepository();
        return repository.m288b();
    }
}
