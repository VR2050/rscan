package com.jbzd.media.movecartoons.p396ui.splash;

import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.Boxing;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p005b.p006a.p007a.p008a.p017r.C0926j;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0920d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.InterfaceC3067i0;
import p379c.p380a.p381a.C2964m;
import p458k.AbstractC4393m0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.splash.SplashViewMode$ping$1", m5320f = "SplashActivity.kt", m5321i = {}, m5322l = {575, 576, 582}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class SplashViewMode$ping$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ String $baseUrl;
    public final /* synthetic */ int $index;
    public final /* synthetic */ Function2<Boolean, String, Unit> $resultCallback;
    public int label;
    public final /* synthetic */ SplashViewMode this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.splash.SplashViewMode$ping$1$1", m5320f = "SplashActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$ping$1$1 */
    public static final class C38941 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ String $baseUrl;
        public final /* synthetic */ Function2<Boolean, String, Unit> $resultCallback;
        public int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public C38941(Function2<? super Boolean, ? super String, Unit> function2, String str, Continuation<? super C38941> continuation) {
            super(2, continuation);
            this.$resultCallback = function2;
            this.$baseUrl = str;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38941(this.$resultCallback, this.$baseUrl, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38941) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            this.$resultCallback.invoke(Boxing.boxBoolean(true), this.$baseUrl);
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.splash.SplashViewMode$ping$1$2", m5320f = "SplashActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$ping$1$2 */
    public static final class C38952 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ String $baseUrl;
        public final /* synthetic */ Function2<Boolean, String, Unit> $resultCallback;
        public int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public C38952(Function2<? super Boolean, ? super String, Unit> function2, String str, Continuation<? super C38952> continuation) {
            super(2, continuation);
            this.$resultCallback = function2;
            this.$baseUrl = str;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38952(this.$resultCallback, this.$baseUrl, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38952) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            this.$resultCallback.invoke(Boxing.boxBoolean(false), this.$baseUrl);
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public SplashViewMode$ping$1(String str, int i2, SplashViewMode splashViewMode, Function2<? super Boolean, ? super String, Unit> function2, Continuation<? super SplashViewMode$ping$1> continuation) {
        super(2, continuation);
        this.$baseUrl = str;
        this.$index = i2;
        this.this$0 = splashViewMode;
        this.$resultCallback = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new SplashViewMode$ping$1(this.$baseUrl, this.$index, this.this$0, this.$resultCallback, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((SplashViewMode$ping$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        try {
        } catch (Exception e2) {
            C2818e.f7655a.m3275a(e2);
            int i3 = this.$index;
            C0925i c0925i = C0925i.f437a;
            if (i3 == C0925i.f439c.size() - 1) {
                C3079m0 c3079m0 = C3079m0.f8432c;
                AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
                C38952 c38952 = new C38952(this.$resultCallback, this.$baseUrl, null);
                this.label = 3;
                if (C2354n.m2471e2(abstractC3077l1, c38952, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                this.this$0.ping(this.$index + 1, this.$resultCallback);
            }
        }
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            C0926j c0926j = C0926j.f441a;
            InterfaceC3067i0<AbstractC4393m0> m230d = ((InterfaceC0920d) C0926j.f442b.m273c(this.$baseUrl).m5687b(InterfaceC0920d.class)).m230d(Intrinsics.stringPlus(this.$baseUrl, "ping"), C0917a.f372a.m224c(null));
            this.label = 1;
            obj = m230d.mo3568s(this);
            if (obj == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                if (i2 == 2) {
                    ResultKt.throwOnFailure(obj);
                } else {
                    if (i2 != 3) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    ResultKt.throwOnFailure(obj);
                }
                return Unit.INSTANCE;
            }
            ResultKt.throwOnFailure(obj);
        }
        C3079m0 c3079m02 = C3079m0.f8432c;
        AbstractC3077l1 abstractC3077l12 = C2964m.f8127b;
        C38941 c38941 = new C38941(this.$resultCallback, this.$baseUrl, null);
        this.label = 2;
        if (C2354n.m2471e2(abstractC3077l12, c38941, this) == coroutine_suspended) {
            return coroutine_suspended;
        }
        return Unit.INSTANCE;
    }
}
