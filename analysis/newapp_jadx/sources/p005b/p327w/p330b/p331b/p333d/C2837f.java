package p005b.p327w.p330b.p331b.p333d;

import androidx.lifecycle.LifecycleCoroutineScope;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import java.util.List;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p383b2.C3008d;
import p379c.p380a.p383b2.C3010f;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

@DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleRefresh$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {250}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.w.b.b.d.f */
/* loaded from: classes2.dex */
public final class C2837f extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f7744c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC3006b<List<T>> f7745e;

    /* renamed from: f */
    public final /* synthetic */ PageRefreshLayout f7746f;

    /* renamed from: g */
    public final /* synthetic */ InterfaceC2846i f7747g;

    /* renamed from: h */
    public final /* synthetic */ BindingAdapter f7748h;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleRefresh$1$1", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.f$a */
    public static final class a<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super List<T>>, Throwable, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ PageRefreshLayout f7749c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(PageRefreshLayout pageRefreshLayout, Continuation<? super a> continuation) {
            super(3, continuation);
            this.f7749c = pageRefreshLayout;
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            return new a(this.f7749c, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            PageRefreshLayout.m3948B(this.f7749c, false, false, 2, null);
            if (this.f7749c.getF8947T0() == 1) {
                PageRefreshLayout.m3950G(this.f7749c, null, false, 3, null);
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.ext.FlowExtKt$lifecycleRefresh$1$2", m5320f = "FlowExt.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.w.b.b.d.f$b */
    public static final class b<T> extends SuspendLambda implements Function3<InterfaceC3007c<? super List<T>>, Throwable, Continuation<? super Unit>, Object> {
        public b(Continuation<? super b> continuation) {
            super(3, continuation);
        }

        @Override // kotlin.jvm.functions.Function3
        public Object invoke(Object obj, Throwable th, Continuation<? super Unit> continuation) {
            new b(continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            C2354n.m2450Z0("lifecycleRefresh:onCompletion");
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            C2354n.m2450Z0("lifecycleRefresh:onCompletion");
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.w.b.b.d.f$c */
    public static final class c extends Lambda implements Function1<BindingAdapter, Boolean> {

        /* renamed from: c */
        public final /* synthetic */ List<T> f7750c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(List<T> list) {
            super(1);
            this.f7750c = list;
        }

        @Override // kotlin.jvm.functions.Function1
        public Boolean invoke(BindingAdapter bindingAdapter) {
            BindingAdapter addData = bindingAdapter;
            Intrinsics.checkNotNullParameter(addData, "$this$addData");
            return Boolean.valueOf(!this.f7750c.isEmpty());
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.w.b.b.d.f$d */
    public static final class d<T> implements InterfaceC3007c<List<T>> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC2846i f7751c;

        /* renamed from: e */
        public final /* synthetic */ PageRefreshLayout f7752e;

        /* renamed from: f */
        public final /* synthetic */ BindingAdapter f7753f;

        public d(InterfaceC2846i interfaceC2846i, PageRefreshLayout pageRefreshLayout, BindingAdapter bindingAdapter) {
            this.f7751c = interfaceC2846i;
            this.f7752e = pageRefreshLayout;
            this.f7753f = bindingAdapter;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            List list = (List) obj;
            LifecycleCoroutineScope scope = this.f7751c.scope();
            Intrinsics.checkNotNullParameter(scope, "<this>");
            InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) scope.getCoroutineContext().get(InterfaceC3053d1.f8393b);
            if (!(interfaceC3053d1 == null ? false : interfaceC3053d1.isCancelled())) {
                PageRefreshLayout.m3951z(this.f7752e, list, this.f7753f, null, new c(list), 4, null);
                PageRefreshLayout pageRefreshLayout = this.f7752e;
                boolean z = !list.isEmpty();
                pageRefreshLayout.f8956c1 = z;
                pageRefreshLayout.f10552f0 = true;
                pageRefreshLayout.f10524J = z;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "super.setEnableLoadMore(enabled)");
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C2837f(InterfaceC3006b<? extends List<T>> interfaceC3006b, PageRefreshLayout pageRefreshLayout, InterfaceC2846i interfaceC2846i, BindingAdapter bindingAdapter, Continuation<? super C2837f> continuation) {
        super(2, continuation);
        this.f7745e = interfaceC3006b;
        this.f7746f = pageRefreshLayout;
        this.f7747g = interfaceC2846i;
        this.f7748h = bindingAdapter;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C2837f(this.f7745e, this.f7746f, this.f7747g, this.f7748h, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C2837f(this.f7745e, this.f7746f, this.f7747g, this.f7748h, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f7744c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b<List<T>> interfaceC3006b = this.f7745e;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C3008d c3008d = new C3008d(new C3010f(C2354n.m2469e0(interfaceC3006b, C3079m0.f8431b), new a(this.f7746f, null)), new b(null));
            d dVar = new d(this.f7747g, this.f7746f, this.f7748h);
            this.f7744c = 1;
            if (c3008d.mo289a(dVar, this) == coroutine_suspended) {
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
