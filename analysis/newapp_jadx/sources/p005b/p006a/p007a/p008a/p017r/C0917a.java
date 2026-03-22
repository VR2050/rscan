package p005b.p006a.p007a.p008a.p017r;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.support.retrofit.Retrofit2ConverterFactory;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.OriginalResponseBody;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.request.BaseRequestBody;
import com.jbzd.media.movecartoons.bean.response.ResponseError;
import java.lang.reflect.GenericDeclaration;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Function;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p017r.p019l.C0936a;
import p005b.p006a.p007a.p008a.p017r.p019l.C0937b;
import p005b.p006a.p007a.p008a.p017r.p019l.C0938c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p303q.p304a.p305a.p306a.p307a.C2720c;
import p005b.p325v.p326a.C2818e;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p426f.p427a.p428a.C4325a;
import p458k.AbstractC4387j0;
import p458k.C4371b0;
import p458k.C4385i0;
import p458k.p459p0.C4401c;
import p458k.p471q0.C4480a;
import p505n.C5015j;

/* renamed from: b.a.a.a.r.a */
/* loaded from: classes2.dex */
public final class C0917a {

    /* renamed from: a */
    @NotNull
    public static final C0917a f372a = new C0917a();

    /* renamed from: b */
    @NotNull
    public static final InterfaceC0920d f373b;

    /* renamed from: b.a.a.a.r.a$a */
    public static final class a extends Lambda implements Function1<Exception, Unit> {

        /* renamed from: c */
        public static final a f374c = new a();

        public a() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Exception exc) {
            Exception it = exc;
            Intrinsics.checkNotNullParameter(it, "it");
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.r.a$b */
    public static final class b extends Lambda implements Function0<Unit> {

        /* renamed from: c */
        public static final b f375c = new b();

        public b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Unit invoke() {
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$doPost$3", m5320f = "Api.kt", m5321i = {}, m5322l = {60, 77, 123, 126}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.a$c */
    public static final class c extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public int f376c;

        /* renamed from: e */
        public final /* synthetic */ boolean f377e;

        /* renamed from: f */
        public final /* synthetic */ String f378f;

        /* renamed from: g */
        public final /* synthetic */ Object f379g;

        /* renamed from: h */
        public final /* synthetic */ boolean f380h;

        /* renamed from: i */
        public final /* synthetic */ Class<T> f381i;

        /* renamed from: j */
        public final /* synthetic */ Function1<T, Unit> f382j;

        /* renamed from: k */
        public final /* synthetic */ Function0<Unit> f383k;

        /* renamed from: l */
        public final /* synthetic */ boolean f384l;

        /* renamed from: m */
        public final /* synthetic */ Function1<Exception, Unit> f385m;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$doPost$3$1", m5320f = "Api.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.a$c$a */
        public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ String f386c;

            /* renamed from: e */
            public final /* synthetic */ Class<T> f387e;

            /* renamed from: f */
            public final /* synthetic */ Function1<T, Unit> f388f;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            public a(String str, Class<T> cls, Function1<? super T, Unit> function1, Continuation<? super a> continuation) {
                super(2, continuation);
                this.f386c = str;
                this.f387e = cls;
                this.f388f = function1;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new a(this.f386c, this.f387e, this.f388f, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                return new a(this.f386c, this.f387e, this.f388f, continuation).invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                boolean z;
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                C0917a c0917a = C0917a.f372a;
                try {
                    JSON.parseObject(this.f386c, this.f387e);
                    z = true;
                } catch (Exception e2) {
                    e2.printStackTrace();
                    z = false;
                }
                if (z) {
                    this.f388f.invoke(JSON.parseObject(this.f386c, this.f387e));
                } else {
                    try {
                        this.f388f.invoke(this.f386c);
                    } catch (Exception unused) {
                        this.f388f.invoke(null);
                    }
                }
                return Unit.INSTANCE;
            }
        }

        /* renamed from: b.a.a.a.r.a$c$b */
        public static final class b extends Lambda implements Function1<TokenBean, Unit> {

            /* renamed from: c */
            public final /* synthetic */ String f389c;

            /* renamed from: e */
            public final /* synthetic */ Class<T> f390e;

            /* renamed from: f */
            public final /* synthetic */ Object f391f;

            /* renamed from: g */
            public final /* synthetic */ Function1<T, Unit> f392g;

            /* renamed from: h */
            public final /* synthetic */ Function1<Exception, Unit> f393h;

            /* renamed from: i */
            public final /* synthetic */ boolean f394i;

            /* renamed from: j */
            public final /* synthetic */ boolean f395j;

            /* renamed from: k */
            public final /* synthetic */ Function0<Unit> f396k;

            /* renamed from: l */
            public final /* synthetic */ boolean f397l;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            public b(String str, Class<T> cls, Object obj, Function1<? super T, Unit> function1, Function1<? super Exception, Unit> function12, boolean z, boolean z2, Function0<Unit> function0, boolean z3) {
                super(1);
                this.f389c = str;
                this.f390e = cls;
                this.f391f = obj;
                this.f392g = function1;
                this.f393h = function12;
                this.f394i = z;
                this.f395j = z2;
                this.f396k = function0;
                this.f397l = z3;
            }

            @Override // kotlin.jvm.functions.Function1
            public Unit invoke(TokenBean tokenBean) {
                TokenBean tokenBean2 = tokenBean;
                C2818e.m3272a(JSON.toJSONString(tokenBean2), new Object[0]);
                if (tokenBean2 != null) {
                    String str = this.f389c;
                    GenericDeclaration genericDeclaration = this.f390e;
                    Object obj = this.f391f;
                    Function function = this.f392g;
                    Function1<Exception, Unit> function1 = this.f393h;
                    boolean z = this.f394i;
                    boolean z2 = this.f395j;
                    Function0<Unit> function0 = this.f396k;
                    boolean z3 = this.f397l;
                    MyApp myApp = MyApp.f9891f;
                    MyApp.m4188i(tokenBean2);
                    C0917a.f372a.m225d(str, genericDeclaration, obj, function, function1, z, z2, function0, z3);
                }
                return Unit.INSTANCE;
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public c(boolean z, String str, Object obj, boolean z2, Class<T> cls, Function1<? super T, Unit> function1, Function0<Unit> function0, boolean z3, Function1<? super Exception, Unit> function12, Continuation<? super c> continuation) {
            super(2, continuation);
            this.f377e = z;
            this.f378f = str;
            this.f379g = obj;
            this.f380h = z2;
            this.f381i = cls;
            this.f382j = function1;
            this.f383k = function0;
            this.f384l = z3;
            this.f385m = function12;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new c(this.f377e, this.f378f, this.f379g, this.f380h, this.f381i, this.f382j, this.f383k, this.f384l, this.f385m, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return ((c) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object m220b;
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.f376c;
            boolean z = true;
            try {
            } catch (Exception e2) {
                Intrinsics.stringPlus("error:", e2.getMessage());
                if (e2 instanceof C0938c) {
                    C0917a c0917a = C0917a.f372a;
                    HashMap hashMap = new HashMap();
                    hashMap.put("device_id", C0887j.m211a());
                    Unit unit = Unit.INSTANCE;
                    C0917a.m221e(c0917a, "user/login", TokenBean.class, hashMap, new b(this.f378f, this.f381i, this.f379g, this.f382j, this.f385m, this.f380h, this.f384l, this.f383k, this.f377e), null, false, false, null, false, 496);
                } else if (e2 instanceof C0937b) {
                    this.f383k.invoke();
                    C0917a c0917a2 = C0917a.f372a;
                    boolean z2 = this.f384l;
                    Function1<Exception, Unit> function1 = this.f385m;
                    boolean z3 = this.f380h;
                    this.f376c = 3;
                    if (c0917a2.m226g(z2, e2, function1, z3, this) == coroutine_suspended) {
                        return coroutine_suspended;
                    }
                } else {
                    C0917a c0917a3 = C0917a.f372a;
                    boolean z4 = this.f384l;
                    Function1<Exception, Unit> function12 = this.f385m;
                    boolean z5 = this.f380h;
                    this.f376c = 4;
                    if (c0917a3.m226g(z4, e2, function12, z5, this) == coroutine_suspended) {
                        return coroutine_suspended;
                    }
                }
            }
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                C0917a c0917a4 = C0917a.f372a;
                String stringPlus = this.f377e ? this.f378f : Intrinsics.stringPlus(C0925i.f437a.m270b(), this.f378f);
                AbstractC4387j0 m224c = c0917a4.m224c(this.f379g);
                this.f376c = 1;
                m220b = C0917a.m220b(c0917a4, stringPlus, m224c, this);
                if (m220b == coroutine_suspended) {
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
                m220b = obj;
            }
            String m219a = C0917a.m219a(C0917a.f372a, (byte[]) m220b);
            if (this.f380h) {
                try {
                    JSON.parseObject(m219a, this.f381i);
                } catch (Exception e3) {
                    e3.printStackTrace();
                    z = false;
                }
                if (z) {
                    this.f382j.invoke(JSON.parseObject(m219a, this.f381i));
                } else {
                    try {
                        this.f382j.invoke(m219a);
                    } catch (Exception unused) {
                        this.f382j.invoke(null);
                    }
                }
            } else {
                C3079m0 c3079m0 = C3079m0.f8432c;
                AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
                a aVar = new a(m219a, this.f381i, this.f382j, null);
                this.f376c = 2;
                if (C2354n.m2471e2(abstractC3077l1, aVar, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            }
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.r.a$d */
    public static final class d extends Lambda implements Function1<Exception, Unit> {

        /* renamed from: c */
        public static final d f398c = new d();

        public d() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Exception exc) {
            Exception it = exc;
            Intrinsics.checkNotNullParameter(it, "it");
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.r.a$e */
    public static final class e extends Lambda implements Function0<Unit> {

        /* renamed from: c */
        public static final e f399c = new e();

        public e() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Unit invoke() {
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api", m5320f = "Api.kt", m5321i = {0, 0, 0, 1}, m5322l = {266, 294}, m5323m = "errorHandler", m5324n = {C1568e.f1949a, "error", "sync", C1568e.f1949a}, m5325s = {"L$0", "L$1", "Z$0", "L$0"})
    /* renamed from: b.a.a.a.r.a$f */
    public static final class f extends ContinuationImpl {

        /* renamed from: c */
        public Object f400c;

        /* renamed from: e */
        public Object f401e;

        /* renamed from: f */
        public boolean f402f;

        /* renamed from: g */
        public /* synthetic */ Object f403g;

        /* renamed from: i */
        public int f405i;

        public f(Continuation<? super f> continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f403g = obj;
            this.f405i |= Integer.MIN_VALUE;
            C0917a c0917a = C0917a.this;
            C0917a c0917a2 = C0917a.f372a;
            return c0917a.m226g(false, null, null, false, this);
        }
    }

    /* renamed from: b.a.a.a.r.a$g */
    public static final class g extends Lambda implements Function1<Exception, Unit> {

        /* renamed from: c */
        public static final g f406c = new g();

        public g() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Exception exc) {
            Exception it = exc;
            Intrinsics.checkNotNullParameter(it, "it");
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$errorHandler$3", m5320f = "Api.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.a$h */
    public static final class h extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ Exception f407c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public h(Exception exc, Continuation<? super h> continuation) {
            super(2, continuation);
            this.f407c = exc;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new h(this.f407c, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return new h(this.f407c, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Exception exc = this.f407c;
            if (exc instanceof C0936a) {
                StringBuilder m586H = C1499a.m586H("error:");
                m586H.append((Object) this.f407c.getMessage());
                m586H.append(",code:");
                m586H.append(((C0936a) this.f407c).f465c);
                m586H.toString();
                MyApp myApp = MyApp.f9891f;
                C4325a.m4899b(MyApp.m4183d(), String.valueOf(this.f407c.getMessage())).show();
            } else if (exc instanceof ConnectException) {
                C2354n.m2451Z1("网络异常，请检查网络设置");
            } else if (exc instanceof SocketTimeoutException) {
                C2354n.m2451Z1("请求超时，请检查网络设置");
            } else if (exc instanceof C5015j) {
                C2354n.m2451Z1("网络异常，请检查网络设置");
            } else {
                C2354n.m2451Z1("加载失败，稍候再试");
            }
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api$errorHandler$4", m5320f = "Api.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.a$i */
    public static final class i extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public final /* synthetic */ Function1<Exception, Unit> f408c;

        /* renamed from: e */
        public final /* synthetic */ Exception f409e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public i(Function1<? super Exception, Unit> function1, Exception exc, Continuation<? super i> continuation) {
            super(2, continuation);
            this.f408c = function1;
            this.f409e = exc;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new i(this.f408c, this.f409e, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            Function1<Exception, Unit> function1 = this.f408c;
            Exception exc = this.f409e;
            new i(function1, exc, continuation);
            Unit unit = Unit.INSTANCE;
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(unit);
            function1.invoke(exc);
            return unit;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            this.f408c.invoke(this.f409e);
            return Unit.INSTANCE;
        }
    }

    static {
        C0926j c0926j = C0926j.f441a;
        C0926j c0926j2 = C0926j.f442b;
        String baseUrl = C0925i.f437a.m270b();
        Objects.requireNonNull(c0926j2);
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        C2720c c2720c = new C2720c(null);
        Retrofit2ConverterFactory create = Retrofit2ConverterFactory.create();
        Intrinsics.checkNotNullExpressionValue(create, "create()");
        C4480a c4480a = new C4480a(new C0923g());
        c4480a.m5264d(C4480a.a.HEADERS);
        Object m5687b = c0926j2.m271a(baseUrl, c2720c, create, c0926j2.m272b(40L, c4480a)).m5687b(InterfaceC0920d.class);
        Intrinsics.checkNotNullExpressionValue(m5687b, "RetrofitUtil.instance.retrofit(NetConfig.getValidBaseUrl()).create(ApiService::class.java)");
        f373b = (InterfaceC0920d) m5687b;
    }

    /* renamed from: a */
    public static final String m219a(C0917a c0917a, byte[] bArr) {
        Charset charset = Charsets.UTF_8;
        String str = new String(bArr, charset);
        byte[] originByteArray = null;
        if (StringsKt__StringsJVMKt.startsWith$default(str, "{", false, 2, null)) {
            ResponseError responseError = (ResponseError) JSON.parseObject(str, ResponseError.class);
            Integer errorCode = responseError.getErrorCode();
            if (errorCode == null || errorCode.intValue() != 2002) {
                String error = responseError.getError();
                Intrinsics.checkNotNullExpressionValue(error, "responseError.error");
                throw new C0936a(error, responseError.getErrorCode());
            }
            String error2 = responseError.getError();
            Intrinsics.checkNotNullExpressionValue(error2, "responseError.error");
            Integer errorCode2 = responseError.getErrorCode();
            Intrinsics.checkNotNullExpressionValue(errorCode2, "responseError.errorCode");
            throw new C0938c(error2, errorCode2.intValue());
        }
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(2, secretKeySpec);
            originByteArray = cipher.doFinal(bArr);
        } catch (Exception e2) {
            System.out.println(e2.toString());
        }
        Intrinsics.checkNotNullExpressionValue(originByteArray, "originByteArray");
        String str2 = new String(originByteArray, charset);
        OriginalResponseBody originalResponseBody = (OriginalResponseBody) JSON.parseObject(str2, OriginalResponseBody.class);
        C2818e.m3274c(str2);
        if (!Intrinsics.areEqual(originalResponseBody.getStatus(), "n")) {
            return originalResponseBody.getData();
        }
        if (originalResponseBody.getErrorCode() == 2002) {
            String error3 = originalResponseBody.getError();
            Intrinsics.checkNotNullExpressionValue(error3, "originalResponseBody.error");
            throw new C0938c(error3, originalResponseBody.getErrorCode());
        }
        String error4 = originalResponseBody.getError();
        Intrinsics.checkNotNullExpressionValue(error4, "originalResponseBody.error");
        throw new C0936a(error4, Integer.valueOf(originalResponseBody.getErrorCode()));
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0026  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object m220b(p005b.p006a.p007a.p008a.p017r.C0917a r5, java.lang.String r6, p458k.AbstractC4387j0 r7, kotlin.coroutines.Continuation r8) {
        /*
            java.util.Objects.requireNonNull(r5)
            boolean r0 = r8 instanceof p005b.p006a.p007a.p008a.p017r.C0919c
            if (r0 == 0) goto L16
            r0 = r8
            b.a.a.a.r.c r0 = (p005b.p006a.p007a.p008a.p017r.C0919c) r0
            int r1 = r0.f432f
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.f432f = r1
            goto L1b
        L16:
            b.a.a.a.r.c r0 = new b.a.a.a.r.c
            r0.<init>(r5, r8)
        L1b:
            java.lang.Object r5 = r0.f430c
            java.lang.Object r8 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r0.f432f
            r2 = 1
            if (r1 == 0) goto L34
            if (r1 != r2) goto L2c
            kotlin.ResultKt.throwOnFailure(r5)
            goto L7a
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            kotlin.ResultKt.throwOnFailure(r5)
            b.w.b.b.a r5 = p005b.p327w.p330b.C2827a.f7670a
            r1 = 0
            java.lang.String r3 = "context"
            if (r5 == 0) goto L91
            java.lang.String r5 = "http.proxyHost"
            java.lang.String r5 = java.lang.System.getProperty(r5)
            java.lang.String r4 = "http.proxyPort"
            java.lang.String r4 = java.lang.System.getProperty(r4)
            if (r4 == 0) goto L4d
            goto L4f
        L4d:
            java.lang.String r4 = "-1"
        L4f:
            int r4 = java.lang.Integer.parseInt(r4)
            boolean r5 = android.text.TextUtils.isEmpty(r5)
            if (r5 != 0) goto L5e
            r5 = -1
            if (r4 == r5) goto L5e
            r5 = 1
            goto L5f
        L5e:
            r5 = 0
        L5f:
            if (r5 != 0) goto L8b
            b.w.b.b.a r5 = p005b.p327w.p330b.C2827a.f7670a
            if (r5 == 0) goto L87
            boolean r5 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2411M0(r5)
            if (r5 == 0) goto L81
            b.a.a.a.r.d r5 = p005b.p006a.p007a.p008a.p017r.C0917a.f373b
            c.a.i0 r5 = r5.m230d(r6, r7)
            r0.f432f = r2
            java.lang.Object r5 = r5.mo3568s(r0)
            if (r5 != r8) goto L7a
            goto L80
        L7a:
            k.m0 r5 = (p458k.AbstractC4393m0) r5
            byte[] r8 = r5.m5007b()
        L80:
            return r8
        L81:
            b.a.a.a.r.l.b r5 = new b.a.a.a.r.l.b
            r5.<init>()
            throw r5
        L87:
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r3)
            throw r1
        L8b:
            b.a.a.a.r.l.d r5 = new b.a.a.a.r.l.d
            r5.<init>()
            throw r5
        L91:
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r3)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.C0917a.m220b(b.a.a.a.r.a, java.lang.String, k.j0, kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* renamed from: e */
    public static /* synthetic */ InterfaceC3053d1 m221e(C0917a c0917a, String str, Class cls, Object obj, Function1 function1, Function1 function12, boolean z, boolean z2, Function0 function0, boolean z3, int i2) {
        return c0917a.m225d(str, cls, (i2 & 4) != 0 ? null : obj, function1, (i2 & 16) != 0 ? a.f374c : function12, (i2 & 32) != 0 ? false : z, (i2 & 64) != 0 ? true : z2, (i2 & 128) != 0 ? b.f375c : null, (i2 & 256) != 0 ? false : z3);
    }

    /* renamed from: f */
    public static InterfaceC3053d1 m222f(C0917a c0917a, String url, Class responseClass, Object obj, Function1 success, Function1 function1, boolean z, boolean z2, Function0 function0, boolean z3, int i2) {
        Object obj2 = (i2 & 4) != 0 ? null : obj;
        Function1 error = (i2 & 16) != 0 ? d.f398c : function1;
        boolean z4 = (i2 & 32) != 0 ? false : z;
        boolean z5 = (i2 & 64) != 0 ? true : z2;
        e netUnavailable = (i2 & 128) != 0 ? e.f399c : null;
        boolean z6 = (i2 & 256) != 0 ? false : z3;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(responseClass, "responseClass");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        Intrinsics.checkNotNullParameter(netUnavailable, "netUnavailable");
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        return C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new C0918b(z6, url, obj2, z4, success, responseClass, netUnavailable, z5, error, null), 2, null);
    }

    /* renamed from: h */
    public static /* synthetic */ Object m223h(C0917a c0917a, boolean z, Exception exc, Function1 function1, boolean z2, Continuation continuation, int i2) {
        if ((i2 & 4) != 0) {
            function1 = g.f406c;
        }
        return c0917a.m226g(z, exc, function1, (i2 & 8) != 0 ? false : z2, continuation);
    }

    @NotNull
    /* renamed from: c */
    public final AbstractC4387j0 m224c(@Nullable Object obj) {
        BaseRequestBody baseRequestBody = new BaseRequestBody();
        baseRequestBody.setDeviceId(C0887j.m211a());
        StringBuilder sb = new StringBuilder();
        MyApp myApp = MyApp.f9891f;
        TokenBean m4186g = MyApp.m4186g();
        byte[] toRequestBody = null;
        sb.append((Object) (m4186g == null ? null : m4186g.token));
        sb.append('_');
        TokenBean m4186g2 = MyApp.m4186g();
        sb.append((Object) (m4186g2 == null ? null : m4186g2.user_id));
        baseRequestBody.setToken(sb.toString());
        baseRequestBody.setData(obj);
        String jsonStr = JSON.toJSONString(baseRequestBody);
        C2818e.m3274c(jsonStr);
        Intrinsics.checkNotNullExpressionValue(jsonStr, "jsonStr");
        byte[] bytes = jsonStr.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, secretKeySpec);
            toRequestBody = cipher.doFinal(bytes);
        } catch (Exception e2) {
            System.out.println(e2.toString());
        }
        C4371b0.a aVar = C4371b0.f11309c;
        C4371b0 m4946b = C4371b0.a.m4946b("application/octet-stream");
        Intrinsics.checkNotNullExpressionValue(toRequestBody, "parameterByteArray");
        int length = (12 & 8) != 0 ? toRequestBody.length : 0;
        Intrinsics.checkParameterIsNotNull(toRequestBody, "content");
        Intrinsics.checkParameterIsNotNull(toRequestBody, "$this$toRequestBody");
        C4401c.m5018c(toRequestBody.length, 0, length);
        return new C4385i0(toRequestBody, m4946b, length, 0);
    }

    @NotNull
    /* renamed from: d */
    public final <T> InterfaceC3053d1 m225d(@NotNull String url, @NotNull Class<T> responseClass, @Nullable Object obj, @NotNull Function1<? super T, Unit> success, @NotNull Function1<? super Exception, Unit> error, boolean z, boolean z2, @NotNull Function0<Unit> netUnavailable, boolean z3) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(responseClass, "responseClass");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        Intrinsics.checkNotNullParameter(netUnavailable, "netUnavailable");
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        return C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new c(z3, url, obj, z, responseClass, success, netUnavailable, z2, error, null), 2, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0025  */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object m226g(boolean r7, java.lang.Exception r8, kotlin.jvm.functions.Function1<? super java.lang.Exception, kotlin.Unit> r9, boolean r10, kotlin.coroutines.Continuation<? super kotlin.Unit> r11) {
        /*
            r6 = this;
            boolean r0 = r11 instanceof p005b.p006a.p007a.p008a.p017r.C0917a.f
            if (r0 == 0) goto L13
            r0 = r11
            b.a.a.a.r.a$f r0 = (p005b.p006a.p007a.p008a.p017r.C0917a.f) r0
            int r1 = r0.f405i
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f405i = r1
            goto L18
        L13:
            b.a.a.a.r.a$f r0 = new b.a.a.a.r.a$f
            r0.<init>(r11)
        L18:
            java.lang.Object r11 = r0.f403g
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f405i
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L49
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r7 = r0.f400c
            java.lang.Exception r7 = (java.lang.Exception) r7
            kotlin.ResultKt.throwOnFailure(r11)
            goto L83
        L31:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L39:
            boolean r10 = r0.f402f
            java.lang.Object r7 = r0.f401e
            r9 = r7
            kotlin.jvm.functions.Function1 r9 = (kotlin.jvm.functions.Function1) r9
            java.lang.Object r7 = r0.f400c
            r8 = r7
            java.lang.Exception r8 = (java.lang.Exception) r8
            kotlin.ResultKt.throwOnFailure(r11)
            goto L66
        L49:
            kotlin.ResultKt.throwOnFailure(r11)
            if (r7 == 0) goto L66
            c.a.m0 r7 = p379c.p380a.C3079m0.f8432c
            c.a.l1 r7 = p379c.p380a.p381a.C2964m.f8127b
            b.a.a.a.r.a$h r11 = new b.a.a.a.r.a$h
            r11.<init>(r8, r5)
            r0.f400c = r8
            r0.f401e = r9
            r0.f402f = r10
            r0.f405i = r4
            java.lang.Object r7 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2471e2(r7, r11, r0)
            if (r7 != r1) goto L66
            return r1
        L66:
            if (r10 == 0) goto L6c
            r9.invoke(r8)
            goto L84
        L6c:
            c.a.m0 r7 = p379c.p380a.C3079m0.f8432c
            c.a.l1 r7 = p379c.p380a.p381a.C2964m.f8127b
            b.a.a.a.r.a$i r10 = new b.a.a.a.r.a$i
            r10.<init>(r9, r8, r5)
            r0.f400c = r8
            r0.f401e = r5
            r0.f405i = r3
            java.lang.Object r7 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2471e2(r7, r10, r0)
            if (r7 != r1) goto L82
            return r1
        L82:
            r7 = r8
        L83:
            r8 = r7
        L84:
            r8.printStackTrace()
            kotlin.Unit r7 = kotlin.Unit.INSTANCE
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.C0917a.m226g(boolean, java.lang.Exception, kotlin.jvm.functions.Function1, boolean, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
