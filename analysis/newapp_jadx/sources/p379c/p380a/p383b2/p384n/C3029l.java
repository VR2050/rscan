package p379c.p380a.p383b2.p384n;

import java.util.Objects;
import kotlin.Result;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.CoroutineStackFrame;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Lambda;
import kotlin.text.StringsKt__IndentKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.l */
/* loaded from: classes2.dex */
public final class C3029l<T> extends ContinuationImpl implements InterfaceC3007c<T>, CoroutineStackFrame {

    /* renamed from: c */
    @JvmField
    public final int f8325c;

    /* renamed from: e */
    public CoroutineContext f8326e;

    /* renamed from: f */
    public Continuation<? super Unit> f8327f;

    /* renamed from: g */
    @JvmField
    @NotNull
    public final InterfaceC3007c<T> f8328g;

    /* renamed from: h */
    @JvmField
    @NotNull
    public final CoroutineContext f8329h;

    /* renamed from: c.a.b2.n.l$a */
    public static final class a extends Lambda implements Function2<Integer, CoroutineContext.Element, Integer> {

        /* renamed from: c */
        public static final a f8330c = new a();

        public a() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public Integer invoke(Integer num, CoroutineContext.Element element) {
            return Integer.valueOf(num.intValue() + 1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C3029l(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull CoroutineContext coroutineContext) {
        super(C3027j.f8323e, EmptyCoroutineContext.INSTANCE);
        this.f8328g = interfaceC3007c;
        this.f8329h = coroutineContext;
        this.f8325c = ((Number) coroutineContext.fold(0, a.f8330c)).intValue();
    }

    /* renamed from: b */
    public final Object m3520b(Continuation<? super Unit> continuation, T t) {
        CoroutineContext coroutineContext = continuation.get$context();
        InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) coroutineContext.get(InterfaceC3053d1.f8393b);
        if (interfaceC3053d1 != null && !interfaceC3053d1.mo3507b()) {
            throw interfaceC3053d1.mo3553q();
        }
        CoroutineContext coroutineContext2 = this.f8326e;
        if (coroutineContext2 != coroutineContext) {
            if (coroutineContext2 instanceof C3025h) {
                StringBuilder m586H = C1499a.m586H("\n            Flow exception transparency is violated:\n                Previous 'emit' call has thrown exception ");
                m586H.append(((C3025h) coroutineContext2).f8321e);
                m586H.append(", but then emission attempt of value '");
                m586H.append(t);
                m586H.append("' has been detected.\n                Emissions from 'catch' blocks are prohibited in order to avoid unspecified behaviour, 'Flow.catch' operator can be used instead.\n                For a more detailed explanation, please refer to Flow documentation.\n            ");
                throw new IllegalStateException(StringsKt__IndentKt.trimIndent(m586H.toString()).toString());
            }
            if (((Number) coroutineContext.fold(0, new C3031n(this))).intValue() != this.f8325c) {
                StringBuilder m590L = C1499a.m590L("Flow invariant is violated:\n", "\t\tFlow was collected in ");
                m590L.append(this.f8329h);
                m590L.append(",\n");
                m590L.append("\t\tbut emission happened in ");
                m590L.append(coroutineContext);
                throw new IllegalStateException(C1499a.m582D(m590L, ".\n", "\t\tPlease refer to 'flow' documentation or use 'flowOn' instead").toString());
            }
            this.f8326e = coroutineContext;
        }
        this.f8327f = continuation;
        Function3<InterfaceC3007c<Object>, Object, Continuation<? super Unit>, Object> function3 = C3030m.f8331a;
        InterfaceC3007c<T> interfaceC3007c = this.f8328g;
        Objects.requireNonNull(interfaceC3007c, "null cannot be cast to non-null type kotlinx.coroutines.flow.FlowCollector<kotlin.Any?>");
        return function3.invoke(interfaceC3007c, t, this);
    }

    @Override // p379c.p380a.p383b2.InterfaceC3007c
    @Nullable
    public Object emit(T t, @NotNull Continuation<? super Unit> continuation) {
        try {
            Object m3520b = m3520b(continuation, t);
            if (m3520b == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(continuation);
            }
            return m3520b == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m3520b : Unit.INSTANCE;
        } catch (Throwable th) {
            this.f8326e = new C3025h(th);
            throw th;
        }
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl, kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public CoroutineStackFrame getCallerFrame() {
        Continuation<? super Unit> continuation = this.f8327f;
        if (!(continuation instanceof CoroutineStackFrame)) {
            continuation = null;
        }
        return (CoroutineStackFrame) continuation;
    }

    @Override // kotlin.coroutines.jvm.internal.ContinuationImpl, kotlin.coroutines.Continuation
    @NotNull
    /* renamed from: getContext */
    public CoroutineContext get$context() {
        CoroutineContext coroutineContext;
        Continuation<? super Unit> continuation = this.f8327f;
        return (continuation == null || (coroutineContext = continuation.get$context()) == null) ? EmptyCoroutineContext.INSTANCE : coroutineContext;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl, kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public Object invokeSuspend(@NotNull Object obj) {
        Throwable m6058exceptionOrNullimpl = Result.m6058exceptionOrNullimpl(obj);
        if (m6058exceptionOrNullimpl != null) {
            this.f8326e = new C3025h(m6058exceptionOrNullimpl);
        }
        Continuation<? super Unit> continuation = this.f8327f;
        if (continuation != null) {
            continuation.resumeWith(obj);
        }
        return IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
    }

    @Override // kotlin.coroutines.jvm.internal.ContinuationImpl, kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public void releaseIntercepted() {
        super.releaseIntercepted();
    }
}
