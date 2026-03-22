package p379c.p380a.p383b2.p384n;

import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2952a;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.q */
/* loaded from: classes2.dex */
public final class C3034q<T> implements InterfaceC3007c<T> {

    /* renamed from: c */
    public final Object f8336c;

    /* renamed from: e */
    public final Function2<T, Continuation<? super Unit>, Object> f8337e;

    /* renamed from: f */
    public final CoroutineContext f8338f;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.internal.UndispatchedContextCollector$emitRef$1", m5320f = "ChannelFlow.kt", m5321i = {0}, m5322l = {224}, m5323m = "invokeSuspend", m5324n = {"it"}, m5325s = {"L$0"})
    /* renamed from: c.a.b2.n.q$a */
    public static final class a extends SuspendLambda implements Function2<T, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public Object f8339c;

        /* renamed from: e */
        public Object f8340e;

        /* renamed from: f */
        public int f8341f;

        /* renamed from: g */
        public final /* synthetic */ InterfaceC3007c f8342g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(InterfaceC3007c interfaceC3007c, Continuation continuation) {
            super(2, continuation);
            this.f8342g = interfaceC3007c;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            a aVar = new a(this.f8342g, continuation);
            aVar.f8339c = obj;
            return aVar;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(Object obj, Continuation<? super Unit> continuation) {
            a aVar = new a(this.f8342g, continuation);
            aVar.f8339c = obj;
            return aVar.invokeSuspend(Unit.INSTANCE);
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.f8341f;
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                Object obj2 = this.f8339c;
                InterfaceC3007c interfaceC3007c = this.f8342g;
                this.f8340e = obj2;
                this.f8341f = 1;
                if (interfaceC3007c.emit(obj2, this) == coroutine_suspended) {
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

    public C3034q(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull CoroutineContext coroutineContext) {
        this.f8338f = coroutineContext;
        this.f8336c = C2952a.m3413b(coroutineContext);
        this.f8337e = new a(interfaceC3007c, null);
    }

    @Override // p379c.p380a.p383b2.InterfaceC3007c
    @Nullable
    public Object emit(T t, @NotNull Continuation<? super Unit> continuation) {
        Object m2475f2 = C2354n.m2475f2(this.f8338f, t, this.f8336c, this.f8337e, continuation);
        return m2475f2 == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m2475f2 : Unit.INSTANCE;
    }
}
