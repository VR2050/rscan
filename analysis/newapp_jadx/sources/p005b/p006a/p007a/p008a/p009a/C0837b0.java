package p005b.p006a.p007a.p008a.p009a;

import android.app.Activity;
import com.alipay.sdk.app.PayTask;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.utils.PayUtils$aliPay$1", m5320f = "PayUtils.kt", m5321i = {}, m5322l = {34}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.a.b0 */
/* loaded from: classes2.dex */
public final class C0837b0 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f225c;

    /* renamed from: e */
    public final /* synthetic */ Activity f226e;

    /* renamed from: f */
    public final /* synthetic */ String f227f;

    /* renamed from: g */
    public final /* synthetic */ Function0<Unit> f228g;

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.utils.PayUtils$aliPay$1$1", m5320f = "PayUtils.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.a.b0$a */
    public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ Function0<Unit> f229c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(Function0<Unit> function0, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f229c = function0;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f229c, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            Function0<Unit> function0 = this.f229c;
            new a(function0, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            function0.invoke();
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            this.f229c.invoke();
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0837b0(Activity activity, String str, Function0<Unit> function0, Continuation<? super C0837b0> continuation) {
        super(2, continuation);
        this.f226e = activity;
        this.f227f = str;
        this.f228g = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C0837b0(this.f226e, this.f227f, this.f228g, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C0837b0(this.f226e, this.f227f, this.f228g, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f225c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            new PayTask(this.f226e).pay(this.f227f, true);
            C3079m0 c3079m0 = C3079m0.f8432c;
            AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
            a aVar = new a(this.f228g, null);
            this.f225c = 1;
            if (C2354n.m2471e2(abstractC3077l1, aVar, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
        }
        return Unit.INSTANCE;
    }
}
