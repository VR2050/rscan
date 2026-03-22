package com.jbzd.media.movecartoons.p396ui.splash;

import android.animation.ObjectAnimator;
import android.widget.LinearLayout;
import androidx.constraintlayout.motion.widget.Key;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.List;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "Lc/a/d1;", "<anonymous>", "(Lc/a/e0;)Lc/a/d1;"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.splash.SplashActivity$main$1", m5320f = "SplashActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class SplashActivity$main$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super InterfaceC3053d1>, Object> {
    public final /* synthetic */ List<AdBean> $adBean;
    private /* synthetic */ Object L$0;
    public int label;
    public final /* synthetic */ SplashActivity this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.splash.SplashActivity$main$1$1", m5320f = "SplashActivity.kt", m5321i = {}, m5322l = {281}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.splash.SplashActivity$main$1$1 */
    public static final class C38931 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ List<AdBean> $adBean;
        public int label;
        public final /* synthetic */ SplashActivity this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public C38931(List<? extends AdBean> list, SplashActivity splashActivity, Continuation<? super C38931> continuation) {
            super(2, continuation);
            this.$adBean = list;
            this.this$0 = splashActivity;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38931(this.$adBean, this.this$0, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38931) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.label;
            boolean z = true;
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                this.label = 1;
                if (C2354n.m2422Q(2000L, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
            }
            List<AdBean> list = this.$adBean;
            if (list != null && !list.isEmpty()) {
                z = false;
            }
            if (!z) {
                SplashActivity splashActivity = this.this$0;
                int i3 = R$id.banner_parent_splash;
                ObjectAnimator ofFloat = ObjectAnimator.ofFloat((LinearLayout) splashActivity.findViewById(i3), Key.ALPHA, 0.0f, 1.0f);
                Intrinsics.checkNotNullExpressionValue(ofFloat, "ofFloat(banner_parent_splash, \"alpha\", 0f, 1f)");
                ofFloat.setDuration(1000L);
                ofFloat.start();
                ((LinearLayout) this.this$0.findViewById(i3)).setVisibility(0);
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public SplashActivity$main$1(List<? extends AdBean> list, SplashActivity splashActivity, Continuation<? super SplashActivity$main$1> continuation) {
        super(2, continuation);
        this.$adBean = list;
        this.this$0 = splashActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        SplashActivity$main$1 splashActivity$main$1 = new SplashActivity$main$1(this.$adBean, this.this$0, continuation);
        splashActivity$main$1.L$0 = obj;
        return splashActivity$main$1;
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super InterfaceC3053d1> continuation) {
        return ((SplashActivity$main$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        ResultKt.throwOnFailure(obj);
        return C2354n.m2435U0((InterfaceC3055e0) this.L$0, null, 0, new C38931(this.$adBean, this.this$0, null), 3, null);
    }
}
