package p005b.p327w.p330b.p331b.p333d;

import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p383b2.C3008d;
import p379c.p380a.p383b2.C3009e;
import p379c.p380a.p383b2.C3010f;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

@DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingView$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {250}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.w.b.b.d.e */
/* loaded from: classes2.dex */
public final class C2836e extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f7730c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC3006b<T> f7731e;

    /* renamed from: f */
    public final /* synthetic */ InterfaceC2846i f7732f;

    /* renamed from: g */
    public final /* synthetic */ boolean f7733g;

    /* renamed from: h */
    public final /* synthetic */ Function1<Throwable, Boolean> f7734h;

    /* renamed from: i */
    public final /* synthetic */ Function1<T, Unit> f7735i;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingView$1$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.e$a */
    public static final class a<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC2846i f7736c;

        /* renamed from: e */
        public final /* synthetic */ boolean f7737e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(InterfaceC2846i interfaceC2846i, boolean z, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f7736c = interfaceC2846i;
            this.f7737e = z;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f7736c, this.f7737e, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(Object obj, Continuation<? super Unit> continuation) {
            InterfaceC2846i interfaceC2846i = this.f7736c;
            boolean z = this.f7737e;
            new a(interfaceC2846i, z, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            interfaceC2846i.loadingView();
            if (z) {
                interfaceC2846i.removeFailedView();
            }
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            this.f7736c.loadingView();
            if (this.f7737e) {
                this.f7736c.removeFailedView();
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingView$1$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.e$b */
    public static final class b<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC2846i f7738c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(InterfaceC2846i interfaceC2846i, Continuation<? super b> continuation) {
            super(3, continuation);
            this.f7738c = interfaceC2846i;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            InterfaceC2846i interfaceC2846i = this.f7738c;
            new b(interfaceC2846i, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            C2354n.m2450Z0("lifecycleLoadingView:onCompletion");
            interfaceC2846i.hideLoading();
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            C2354n.m2450Z0("lifecycleLoadingView:onCompletion");
            this.f7738c.hideLoading();
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingView$1$3", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.e$c */
    public static final class c<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public /* synthetic */ Object f7739c;

        /* renamed from: e */
        public final /* synthetic */ Function1<Throwable, Boolean> f7740e;

        /* renamed from: f */
        public final /* synthetic */ boolean f7741f;

        /* renamed from: g */
        public final /* synthetic */ InterfaceC2846i f7742g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public c(Function1<? super Throwable, Boolean> function1, boolean z, InterfaceC2846i interfaceC2846i, Continuation<? super c> continuation) {
            super(3, continuation);
            this.f7740e = function1;
            this.f7741f = z;
            this.f7742g = interfaceC2846i;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            c cVar = new c(this.f7740e, this.f7741f, this.f7742g, continuation);
            cVar.f7739c = th;
            return cVar.invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Throwable th = (Throwable) this.f7739c;
            Function1<Throwable, Boolean> function1 = this.f7740e;
            if (function1 == null || !function1.invoke(th).booleanValue()) {
                if (this.f7741f) {
                    this.f7742g.showFailedView();
                } else {
                    this.f7742g.onError(th);
                }
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.w.b.b.d.e$d */
    public static final class d<T> implements InterfaceC3007c<T> {

        /* renamed from: c */
        public final /* synthetic */ Function1 f7743c;

        public d(Function1 function1) {
            this.f7743c = function1;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            Object invoke = this.f7743c.invoke(obj);
            return invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? invoke : Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C2836e(InterfaceC3006b<? extends T> interfaceC3006b, InterfaceC2846i interfaceC2846i, boolean z, Function1<? super Throwable, Boolean> function1, Function1<? super T, Unit> function12, Continuation<? super C2836e> continuation) {
        super(2, continuation);
        this.f7731e = interfaceC3006b;
        this.f7732f = interfaceC2846i;
        this.f7733g = z;
        this.f7734h = function1;
        this.f7735i = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C2836e(this.f7731e, this.f7732f, this.f7733g, this.f7734h, this.f7735i, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C2836e(this.f7731e, this.f7732f, this.f7733g, this.f7734h, this.f7735i, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f7730c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b<T> interfaceC3006b = this.f7731e;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C3010f c3010f = new C3010f(new C3008d(new C3009e(C2354n.m2469e0(interfaceC3006b, C3079m0.f8431b), new a(this.f7732f, this.f7733g, null)), new b(this.f7732f, null)), new c(this.f7734h, this.f7733g, this.f7732f, null));
            d dVar = new d(this.f7735i);
            this.f7730c = 1;
            if (c3010f.mo289a(dVar, this) == coroutine_suspended) {
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
