package p005b.p327w.p330b.p331b.p333d;

import androidx.lifecycle.MutableLiveData;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
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
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p331b.p335f.C2849b;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p383b2.C3008d;
import p379c.p380a.p383b2.C3009e;
import p379c.p380a.p383b2.C3010f;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

@DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {250}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.w.b.b.d.d */
/* loaded from: classes2.dex */
public final class C2835d extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f7717c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC3006b<T> f7718e;

    /* renamed from: f */
    public final /* synthetic */ BaseViewModel f7719f;

    /* renamed from: g */
    public final /* synthetic */ Function1<Throwable, Boolean> f7720g;

    /* renamed from: h */
    public final /* synthetic */ boolean f7721h;

    /* renamed from: i */
    public final /* synthetic */ Function1<T, Unit> f7722i;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$2$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.d$a */
    public static final class a<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ BaseViewModel f7723c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(BaseViewModel baseViewModel, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f7723c = baseViewModel;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f7723c, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(Object obj, Continuation<? super Unit> continuation) {
            return new a(this.f7723c, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            this.f7723c.getLoading().setValue(new C2848a(true, null, false, true, 6));
            this.f7723c.getNetError().setValue(new C2849b(false, "", false));
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$2$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.d$b */
    public static final class b<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ BaseViewModel f7724c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(BaseViewModel baseViewModel, Continuation<? super b> continuation) {
            super(3, continuation);
            this.f7724c = baseViewModel;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            return new b(this.f7724c, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            C2354n.m2450Z0("lifecycleLoadingDialog:onCompletion");
            this.f7724c.getLoading().setValue(new C2848a(false, null, false, true, 6));
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleLoadingDialog$2$3", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.d$c */
    public static final class c<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public /* synthetic */ Object f7725c;

        /* renamed from: e */
        public final /* synthetic */ Function1<Throwable, Boolean> f7726e;

        /* renamed from: f */
        public final /* synthetic */ BaseViewModel f7727f;

        /* renamed from: g */
        public final /* synthetic */ boolean f7728g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public c(Function1<? super Throwable, Boolean> function1, BaseViewModel baseViewModel, boolean z, Continuation<? super c> continuation) {
            super(3, continuation);
            this.f7726e = function1;
            this.f7727f = baseViewModel;
            this.f7728g = z;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            c cVar = new c(this.f7726e, this.f7727f, this.f7728g, continuation);
            cVar.f7725c = th;
            return cVar.invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Throwable th = (Throwable) this.f7725c;
            Function1<Throwable, Boolean> function1 = this.f7726e;
            if (function1 == null || !function1.invoke(th).booleanValue()) {
                MutableLiveData<C2849b> netError = this.f7727f.getNetError();
                String message = th.getMessage();
                if (message == null) {
                    message = "";
                }
                netError.setValue(new C2849b(true, message, this.f7728g));
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.w.b.b.d.d$d */
    public static final class d<T> implements InterfaceC3007c<T> {

        /* renamed from: c */
        public final /* synthetic */ Function1 f7729c;

        public d(Function1 function1) {
            this.f7729c = function1;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            Object invoke = this.f7729c.invoke(obj);
            return invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? invoke : Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C2835d(InterfaceC3006b<? extends T> interfaceC3006b, BaseViewModel baseViewModel, Function1<? super Throwable, Boolean> function1, boolean z, Function1<? super T, Unit> function12, Continuation<? super C2835d> continuation) {
        super(2, continuation);
        this.f7718e = interfaceC3006b;
        this.f7719f = baseViewModel;
        this.f7720g = function1;
        this.f7721h = z;
        this.f7722i = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C2835d(this.f7718e, this.f7719f, this.f7720g, this.f7721h, this.f7722i, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C2835d(this.f7718e, this.f7719f, this.f7720g, this.f7721h, this.f7722i, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f7717c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b<T> interfaceC3006b = this.f7718e;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C3010f c3010f = new C3010f(new C3008d(new C3009e(C2354n.m2469e0(interfaceC3006b, C3079m0.f8431b), new a(this.f7719f, null)), new b(this.f7719f, null)), new c(this.f7720g, this.f7719f, this.f7721h, null));
            d dVar = new d(this.f7722i);
            this.f7717c = 1;
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
