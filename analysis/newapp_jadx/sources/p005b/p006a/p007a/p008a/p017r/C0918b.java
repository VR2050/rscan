package p005b.p006a.p007a.p008a.p017r;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.asm.Opcodes;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import java.util.HashMap;
import java.util.List;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p017r.p019l.C0937b;
import p005b.p006a.p007a.p008a.p017r.p019l.C0938c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p458k.AbstractC4387j0;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$doPostToArray$3", m5320f = "Api.kt", m5321i = {}, m5322l = {147, 156, Opcodes.IFNULL, 201}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.r.b */
/* loaded from: classes2.dex */
public final class C0918b extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f410c;

    /* renamed from: e */
    public final /* synthetic */ boolean f411e;

    /* renamed from: f */
    public final /* synthetic */ String f412f;

    /* renamed from: g */
    public final /* synthetic */ Object f413g;

    /* renamed from: h */
    public final /* synthetic */ boolean f414h;

    /* renamed from: i */
    public final /* synthetic */ Function1<List<? extends T>, Unit> f415i;

    /* renamed from: j */
    public final /* synthetic */ Class<T> f416j;

    /* renamed from: k */
    public final /* synthetic */ Function0<Unit> f417k;

    /* renamed from: l */
    public final /* synthetic */ boolean f418l;

    /* renamed from: m */
    public final /* synthetic */ Function1<Exception, Unit> f419m;

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$doPostToArray$3$1", m5320f = "Api.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.b$a */
    public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ Function1<List<? extends T>, Unit> f420c;

        /* renamed from: e */
        public final /* synthetic */ String f421e;

        /* renamed from: f */
        public final /* synthetic */ Class<T> f422f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public a(Function1<? super List<? extends T>, Unit> function1, String str, Class<T> cls, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f420c = function1;
            this.f421e = str;
            this.f422f = cls;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f420c, this.f421e, this.f422f, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            Function1<List<? extends T>, Unit> function1 = this.f420c;
            String str = this.f421e;
            Class<T> cls = this.f422f;
            new a(function1, str, cls, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            function1.invoke(JSON.parseArray(str, cls));
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            this.f420c.invoke(JSON.parseArray(this.f421e, this.f422f));
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.r.b$b */
    public static final class b extends Lambda implements Function1<TokenBean, Unit> {

        /* renamed from: c */
        public final /* synthetic */ String f423c;

        /* renamed from: e */
        public final /* synthetic */ Class<T> f424e;

        /* renamed from: f */
        public final /* synthetic */ Object f425f;

        /* renamed from: g */
        public final /* synthetic */ Function1<List<? extends T>, Unit> f426g;

        /* renamed from: h */
        public final /* synthetic */ Function1<Exception, Unit> f427h;

        /* renamed from: i */
        public final /* synthetic */ boolean f428i;

        /* renamed from: j */
        public final /* synthetic */ boolean f429j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public b(String str, Class<T> cls, Object obj, Function1<? super List<? extends T>, Unit> function1, Function1<? super Exception, Unit> function12, boolean z, boolean z2) {
            super(1);
            this.f423c = str;
            this.f424e = cls;
            this.f425f = obj;
            this.f426g = function1;
            this.f427h = function12;
            this.f428i = z;
            this.f429j = z2;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(TokenBean tokenBean) {
            TokenBean tokenBean2 = tokenBean;
            if (tokenBean2 != null) {
                String str = this.f423c;
                Class<T> cls = this.f424e;
                Object obj = this.f425f;
                Function1<List<? extends T>, Unit> function1 = this.f426g;
                Function1<Exception, Unit> function12 = this.f427h;
                boolean z = this.f428i;
                boolean z2 = this.f429j;
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(tokenBean2);
                C0917a.m222f(C0917a.f372a, str, cls, obj, function1, function12, z, z2, null, false, 384);
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0918b(boolean z, String str, Object obj, boolean z2, Function1<? super List<? extends T>, Unit> function1, Class<T> cls, Function0<Unit> function0, boolean z3, Function1<? super Exception, Unit> function12, Continuation<? super C0918b> continuation) {
        super(2, continuation);
        this.f411e = z;
        this.f412f = str;
        this.f413g = obj;
        this.f414h = z2;
        this.f415i = function1;
        this.f416j = cls;
        this.f417k = function0;
        this.f418l = z3;
        this.f419m = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C0918b(this.f411e, this.f412f, this.f413g, this.f414h, this.f415i, this.f416j, this.f417k, this.f418l, this.f419m, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return ((C0918b) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f410c;
        try {
        } catch (Exception e2) {
            Intrinsics.stringPlus("error:", e2.getMessage());
            if (e2 instanceof C0938c) {
                new HashMap().put("deviceId", C0887j.m211a());
                C0917a c0917a = C0917a.f372a;
                HashMap hashMap = new HashMap();
                hashMap.put("device_id", C0887j.m211a());
                Unit unit = Unit.INSTANCE;
                C0917a.m221e(c0917a, "user/login", TokenBean.class, hashMap, new b(this.f412f, this.f416j, this.f413g, this.f415i, this.f419m, this.f414h, this.f418l), null, false, false, null, false, 496);
            } else if (e2 instanceof C0937b) {
                this.f417k.invoke();
                C0917a c0917a2 = C0917a.f372a;
                boolean z = this.f418l;
                Function1<Exception, Unit> function1 = this.f419m;
                this.f410c = 3;
                if (C0917a.m223h(c0917a2, z, e2, function1, false, this, 8) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                C0917a c0917a3 = C0917a.f372a;
                boolean z2 = this.f418l;
                Function1<Exception, Unit> function12 = this.f419m;
                this.f410c = 4;
                if (C0917a.m223h(c0917a3, z2, e2, function12, false, this, 8) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            }
        }
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            C0917a c0917a4 = C0917a.f372a;
            String stringPlus = this.f411e ? this.f412f : Intrinsics.stringPlus(C0925i.f437a.m270b(), this.f412f);
            AbstractC4387j0 m224c = c0917a4.m224c(this.f413g);
            this.f410c = 1;
            obj = C0917a.m220b(c0917a4, stringPlus, m224c, this);
            if (obj == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                if (i2 == 2) {
                    ResultKt.throwOnFailure(obj);
                } else {
                    if (i2 != 3 && i2 != 4) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    ResultKt.throwOnFailure(obj);
                }
                return Unit.INSTANCE;
            }
            ResultKt.throwOnFailure(obj);
        }
        String m219a = C0917a.m219a(C0917a.f372a, (byte[]) obj);
        if (this.f414h) {
            this.f415i.invoke(JSON.parseArray(m219a, this.f416j));
        } else {
            C3079m0 c3079m0 = C3079m0.f8432c;
            AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
            a aVar = new a(this.f415i, m219a, this.f416j, null);
            this.f410c = 2;
            if (C2354n.m2471e2(abstractC3077l1, aVar, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        }
        return Unit.INSTANCE;
    }
}
