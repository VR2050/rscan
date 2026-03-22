package p005b.p006a.p007a.p008a.p017r.p018k;

import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.p019l.C0936a;
import p379c.p380a.C3069j;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.p383b2.InterfaceC3007c;
import p505n.C5030y;
import p505n.InterfaceC4983d;
import p505n.InterfaceC5011f;

/* JADX INFO: Add missing generic type declarations: [T] */
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.converter.BodyCallAdapter$adapt$1", m5320f = "ResponseCallAdapter.kt", m5321i = {}, m5322l = {71, 46}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.r.k.e */
/* loaded from: classes2.dex */
public final class C0931e<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public Object f451c;

    /* renamed from: e */
    public int f452e;

    /* renamed from: f */
    public /* synthetic */ Object f453f;

    /* renamed from: g */
    public final /* synthetic */ InterfaceC4983d<T> f454g;

    /* renamed from: b.a.a.a.r.k.e$a */
    public static final class a implements InterfaceC5011f<T> {

        /* renamed from: a */
        public final /* synthetic */ InterfaceC3066i<T> f455a;

        /* JADX WARN: Multi-variable type inference failed */
        public a(InterfaceC3066i<? super T> interfaceC3066i) {
            this.f455a = interfaceC3066i;
        }

        @Override // p505n.InterfaceC5011f
        /* renamed from: a */
        public void mo275a(@NotNull InterfaceC4983d<T> call, @NotNull Throwable t) {
            Intrinsics.checkNotNullParameter(call, "call");
            Intrinsics.checkNotNullParameter(t, "t");
            InterfaceC3066i<T> interfaceC3066i = this.f455a;
            Result.Companion companion = Result.INSTANCE;
            interfaceC3066i.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(t)));
        }

        @Override // p505n.InterfaceC5011f
        /* renamed from: b */
        public void mo276b(@NotNull InterfaceC4983d<T> call, @NotNull C5030y<T> response) {
            Intrinsics.checkNotNullParameter(call, "call");
            Intrinsics.checkNotNullParameter(response, "response");
            try {
                if (!response.m5685a()) {
                    String str = response.f12957a.f11487g;
                    Intrinsics.checkNotNullExpressionValue(str, "response.message()");
                    throw new C0936a(str, Integer.valueOf(response.f12957a.f11488h));
                }
                InterfaceC3066i<T> interfaceC3066i = this.f455a;
                T t = response.f12958b;
                Result.Companion companion = Result.INSTANCE;
                interfaceC3066i.resumeWith(Result.m6055constructorimpl(t));
            } catch (Exception e2) {
                InterfaceC3066i<T> interfaceC3066i2 = this.f455a;
                Result.Companion companion2 = Result.INSTANCE;
                interfaceC3066i2.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(e2)));
            }
        }
    }

    /* renamed from: b.a.a.a.r.k.e$b */
    public static final class b extends Lambda implements Function1<Throwable, Unit> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC4983d<T> f456c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(InterfaceC4983d<T> interfaceC4983d) {
            super(1);
            this.f456c = interfaceC4983d;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Throwable th) {
            this.f456c.cancel();
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0931e(InterfaceC4983d<T> interfaceC4983d, Continuation<? super C0931e> continuation) {
        super(2, continuation);
        this.f454g = interfaceC4983d;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        C0931e c0931e = new C0931e(this.f454g, continuation);
        c0931e.f453f = obj;
        return c0931e;
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(Object obj, Continuation<? super Unit> continuation) {
        C0931e c0931e = new C0931e(this.f454g, continuation);
        c0931e.f453f = (InterfaceC3007c) obj;
        return c0931e.invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        InterfaceC3007c interfaceC3007c;
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f452e;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            interfaceC3007c = (InterfaceC3007c) this.f453f;
            InterfaceC4983d<T> interfaceC4983d = this.f454g;
            this.f453f = interfaceC4983d;
            this.f451c = interfaceC3007c;
            this.f452e = 1;
            C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(this), 1);
            c3069j.m3602A();
            interfaceC4983d.mo5652o(new a(c3069j));
            c3069j.mo3562f(new b(interfaceC4983d));
            obj = c3069j.m3612u();
            if (obj == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(this);
            }
            if (obj == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                if (i2 != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
                return Unit.INSTANCE;
            }
            interfaceC3007c = (InterfaceC3007c) this.f451c;
            ResultKt.throwOnFailure(obj);
        }
        this.f453f = null;
        this.f451c = null;
        this.f452e = 2;
        if (interfaceC3007c.emit(obj, this) == coroutine_suspended) {
            return coroutine_suspended;
        }
        return Unit.INSTANCE;
    }
}
