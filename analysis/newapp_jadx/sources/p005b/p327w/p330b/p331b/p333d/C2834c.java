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

@DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {250}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.w.b.b.d.c */
/* loaded from: classes2.dex */
public final class C2834c extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f7703c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC3006b<T> f7704e;

    /* renamed from: f */
    public final /* synthetic */ InterfaceC2846i f7705f;

    /* renamed from: g */
    public final /* synthetic */ boolean f7706g;

    /* renamed from: h */
    public final /* synthetic */ Function1<Throwable, Boolean> f7707h;

    /* renamed from: i */
    public final /* synthetic */ Function1<T, Unit> f7708i;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$1$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.c$a */
    public static final class a<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC2846i f7709c;

        /* renamed from: e */
        public final /* synthetic */ boolean f7710e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(InterfaceC2846i interfaceC2846i, boolean z, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f7709c = interfaceC2846i;
            this.f7710e = z;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f7709c, this.f7710e, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(Object obj, Continuation<? super Unit> continuation) {
            InterfaceC2846i interfaceC2846i = this.f7709c;
            boolean z = this.f7710e;
            new a(interfaceC2846i, z, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            interfaceC2846i.loadingDialog();
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
            this.f7709c.loadingDialog();
            if (this.f7710e) {
                this.f7709c.removeFailedView();
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$1$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.c$b */
    public static final class b<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC2846i f7711c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(InterfaceC2846i interfaceC2846i, Continuation<? super b> continuation) {
            super(3, continuation);
            this.f7711c = interfaceC2846i;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            InterfaceC2846i interfaceC2846i = this.f7711c;
            new b(interfaceC2846i, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            C2354n.m2450Z0("lifecycleLoadingDialog:onCompletion");
            interfaceC2846i.hideLoading();
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            C2354n.m2450Z0("lifecycleLoadingDialog:onCompletion");
            this.f7711c.hideLoading();
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$1$3", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.c$c */
    public static final class c<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public /* synthetic */ Object f7712c;

        /* renamed from: e */
        public final /* synthetic */ Function1<Throwable, Boolean> f7713e;

        /* renamed from: f */
        public final /* synthetic */ boolean f7714f;

        /* renamed from: g */
        public final /* synthetic */ InterfaceC2846i f7715g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public c(Function1<? super Throwable, Boolean> function1, boolean z, InterfaceC2846i interfaceC2846i, Continuation<? super c> continuation) {
            super(3, continuation);
            this.f7713e = function1;
            this.f7714f = z;
            this.f7715g = interfaceC2846i;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            c cVar = new c(this.f7713e, this.f7714f, this.f7715g, continuation);
            cVar.f7712c = th;
            return cVar.invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Throwable th = (Throwable) this.f7712c;
            Function1<Throwable, Boolean> function1 = this.f7713e;
            if (function1 == null || !function1.invoke(th).booleanValue()) {
                if (this.f7714f) {
                    this.f7715g.showFailedView();
                } else {
                    this.f7715g.onError(th);
                }
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.w.b.b.d.c$d */
    public static final class d<T> implements InterfaceC3007c<T> {

        /* renamed from: c */
        public final /* synthetic */ Function1 f7716c;

        public d(Function1 function1) {
            this.f7716c = function1;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            Object invoke = this.f7716c.invoke(obj);
            return invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? invoke : Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C2834c(InterfaceC3006b<? extends T> interfaceC3006b, InterfaceC2846i interfaceC2846i, boolean z, Function1<? super Throwable, Boolean> function1, Function1<? super T, Unit> function12, Continuation<? super C2834c> continuation) {
        super(2, continuation);
        this.f7704e = interfaceC3006b;
        this.f7705f = interfaceC2846i;
        this.f7706g = z;
        this.f7707h = function1;
        this.f7708i = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C2834c(this.f7704e, this.f7705f, this.f7706g, this.f7707h, this.f7708i, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C2834c(this.f7704e, this.f7705f, this.f7706g, this.f7707h, this.f7708i, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f7703c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b<T> interfaceC3006b = this.f7704e;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C3010f c3010f = new C3010f(new C3008d(new C3009e(C2354n.m2469e0(interfaceC3006b, C3079m0.f8431b), new a(this.f7705f, this.f7706g, null)), new b(this.f7705f, null)), new c(this.f7707h, this.f7706g, this.f7705f, null));
            d dVar = new d(this.f7708i);
            this.f7703c = 1;
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
