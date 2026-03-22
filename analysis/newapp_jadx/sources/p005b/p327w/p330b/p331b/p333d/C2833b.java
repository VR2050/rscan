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
import p005b.p327w.p330b.p331b.p335f.C2849b;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p383b2.C3008d;
import p379c.p380a.p383b2.C3010f;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

@DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycle$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {250}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.w.b.b.d.b */
/* loaded from: classes2.dex */
public final class C2833b extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f7692c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC3006b<T> f7693e;

    /* renamed from: f */
    public final /* synthetic */ BaseViewModel f7694f;

    /* renamed from: g */
    public final /* synthetic */ boolean f7695g;

    /* renamed from: h */
    public final /* synthetic */ Function1<Throwable, Unit> f7696h;

    /* renamed from: i */
    public final /* synthetic */ Function1<T, Unit> f7697i;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycle$2$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.b$a */
    public static final class a<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {
        public a(Continuation<? super a> continuation) {
            super(3, continuation);
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            new a(continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            C2354n.m2450Z0("lifecycle:onCompletion");
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            C2354n.m2450Z0("lifecycle:onCompletion");
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycle$2$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.b$b */
    public static final class b<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super T>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public /* synthetic */ Object f7698c;

        /* renamed from: e */
        public final /* synthetic */ BaseViewModel f7699e;

        /* renamed from: f */
        public final /* synthetic */ boolean f7700f;

        /* renamed from: g */
        public final /* synthetic */ Function1<Throwable, Unit> f7701g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public b(BaseViewModel baseViewModel, boolean z, Function1<? super Throwable, Unit> function1, Continuation<? super b> continuation) {
            super(3, continuation);
            this.f7699e = baseViewModel;
            this.f7700f = z;
            this.f7701g = function1;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            b bVar = new b(this.f7699e, this.f7700f, this.f7701g, continuation);
            bVar.f7698c = th;
            return bVar.invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Throwable th = (Throwable) this.f7698c;
            MutableLiveData<C2849b> netError = this.f7699e.getNetError();
            String message = th.getMessage();
            if (message == null) {
                message = "";
            }
            netError.setValue(new C2849b(true, message, this.f7700f));
            Function1<Throwable, Unit> function1 = this.f7701g;
            if (function1 != null) {
                function1.invoke(th);
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.w.b.b.d.b$c */
    public static final class c<T> implements InterfaceC3007c<T> {

        /* renamed from: c */
        public final /* synthetic */ Function1 f7702c;

        public c(Function1 function1) {
            this.f7702c = function1;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            Object invoke = this.f7702c.invoke(obj);
            return invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? invoke : Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C2833b(InterfaceC3006b<? extends T> interfaceC3006b, BaseViewModel baseViewModel, boolean z, Function1<? super Throwable, Unit> function1, Function1<? super T, Unit> function12, Continuation<? super C2833b> continuation) {
        super(2, continuation);
        this.f7693e = interfaceC3006b;
        this.f7694f = baseViewModel;
        this.f7695g = z;
        this.f7696h = function1;
        this.f7697i = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C2833b(this.f7693e, this.f7694f, this.f7695g, this.f7696h, this.f7697i, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C2833b(this.f7693e, this.f7694f, this.f7695g, this.f7696h, this.f7697i, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f7692c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b<T> interfaceC3006b = this.f7693e;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C3010f c3010f = new C3010f(new C3008d(C2354n.m2469e0(interfaceC3006b, C3079m0.f8431b), new a(null)), new b(this.f7694f, this.f7695g, this.f7696h, null));
            c cVar = new c(this.f7697i);
            this.f7692c = 1;
            if (c3010f.mo289a(cVar, this) == coroutine_suspended) {
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
