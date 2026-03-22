package p005b.p006a.p007a.p008a.p017r.p022o;

import android.os.Environment;
import com.alibaba.fastjson.asm.Opcodes;
import com.alibaba.fastjson.support.retrofit.Retrofit2ConverterFactory;
import com.jbzd.media.movecartoons.bean.UploadVideoResponse;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
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
import kotlin.jvm.internal.Ref;
import org.conscrypt.EvpMdRef;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0923g;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0920d;
import p005b.p006a.p007a.p008a.p017r.p020m.C0942c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p303q.p304a.p305a.p306a.p307a.C2720c;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p458k.C4374d;
import p458k.C4375d0;
import p458k.p471q0.C4480a;
import p505n.C5031z;

/* renamed from: b.a.a.a.r.o.d */
/* loaded from: classes2.dex */
public final class C0950d {

    /* renamed from: a */
    @NotNull
    public final String f519a;

    /* renamed from: b */
    @NotNull
    public final String f520b;

    /* renamed from: c */
    @NotNull
    public final String f521c;

    /* renamed from: d */
    @NotNull
    public final Function1<UploadVideoResponse.DataBean, Unit> f522d;

    /* renamed from: e */
    @NotNull
    public final Function1<String, Unit> f523e;

    /* renamed from: f */
    @Nullable
    public a f524f;

    /* renamed from: g */
    public String f525g;

    /* renamed from: h */
    @NotNull
    public final Lazy f526h;

    /* renamed from: i */
    @NotNull
    public final Lazy f527i;

    /* renamed from: j */
    @NotNull
    public final Lazy f528j;

    /* renamed from: k */
    public final long f529k;

    /* renamed from: l */
    @NotNull
    public final Lazy f530l;

    /* renamed from: m */
    public int f531m;

    /* renamed from: n */
    @NotNull
    public final Lazy f532n;

    /* renamed from: o */
    public int f533o;

    /* renamed from: b.a.a.a.r.o.d$a */
    public interface a {
        void onProgress(int i2, @NotNull String str);

        void onTotal(int i2);
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController", m5320f = "UploadVideoController.kt", m5321i = {0, 1}, m5322l = {147, Opcodes.DCMPL, Opcodes.IFNE, Opcodes.IF_ICMPEQ}, m5323m = "checkUpload", m5324n = {"this", "this"}, m5325s = {"L$0", "L$0"})
    /* renamed from: b.a.a.a.r.o.d$b */
    public static final class b extends ContinuationImpl {

        /* renamed from: c */
        public Object f534c;

        /* renamed from: e */
        public /* synthetic */ Object f535e;

        /* renamed from: g */
        public int f537g;

        public b(Continuation<? super b> continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f535e = obj;
            this.f537g |= Integer.MIN_VALUE;
            return C0950d.this.m295c(this);
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController$checkUpload$2", m5320f = "UploadVideoController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.o.d$c */
    public static final class c extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: e */
        public final /* synthetic */ UploadVideoResponse f539e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(UploadVideoResponse uploadVideoResponse, Continuation<? super c> continuation) {
            super(2, continuation);
            this.f539e = uploadVideoResponse;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return C0950d.this.new c(this.f539e, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return C0950d.this.new c(this.f539e, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            ResultKt.throwOnFailure(obj);
            Function1<UploadVideoResponse.DataBean, Unit> function1 = C0950d.this.f522d;
            UploadVideoResponse.DataBean data = this.f539e.getData();
            Intrinsics.checkNotNullExpressionValue(data, "response.data");
            function1.invoke(data);
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.r.o.d$d */
    public static final class d extends Lambda implements Function0<File> {
        public d() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public File invoke() {
            return new File(C0950d.this.f520b);
        }
    }

    /* renamed from: b.a.a.a.r.o.d$e */
    public static final class e extends Lambda implements Function0<Long> {
        public e() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Long invoke() {
            return Long.valueOf(C0950d.m293a(C0950d.this).length());
        }
    }

    /* renamed from: b.a.a.a.r.o.d$f */
    public static final class f extends Lambda implements Function0<String> {
        public f() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public String invoke() {
            File m293a = C0950d.m293a(C0950d.this);
            if (!m293a.isFile()) {
                return null;
            }
            byte[] bArr = new byte[1024];
            try {
                MessageDigest messageDigest = MessageDigest.getInstance(EvpMdRef.MD5.JCA_NAME);
                FileInputStream fileInputStream = new FileInputStream(m293a);
                while (true) {
                    int read = fileInputStream.read(bArr, 0, 1024);
                    if (read == -1) {
                        break;
                    }
                    messageDigest.update(bArr, 0, read);
                }
                fileInputStream.close();
                byte[] digest = messageDigest.digest();
                StringBuilder sb = new StringBuilder("");
                if (digest == null || digest.length <= 0) {
                    return null;
                }
                for (byte b2 : digest) {
                    String hexString = Integer.toHexString(b2 & 255);
                    if (hexString.length() < 2) {
                        sb.append(0);
                    }
                    sb.append(hexString);
                }
                return sb.toString();
            } catch (Exception e2) {
                e2.printStackTrace();
                return null;
            }
        }
    }

    /* renamed from: b.a.a.a.r.o.d$g */
    public static final class g extends Lambda implements Function0<InterfaceC0920d> {
        public g() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public InterfaceC0920d invoke() {
            C5031z.b bVar = new C5031z.b();
            bVar.m5693b(C0950d.this.f519a);
            bVar.f12973e.add(new C2720c(null));
            bVar.m5692a(Retrofit2ConverterFactory.create());
            Objects.requireNonNull(C0950d.this);
            File downloadCacheDirectory = Environment.getDownloadCacheDirectory();
            C4480a c4480a = new C4480a(new C0923g());
            c4480a.m5264d(C4480a.a.BODY);
            C4375d0.a aVar = new C4375d0.a();
            TimeUnit timeUnit = TimeUnit.SECONDS;
            aVar.m4957b(40L, timeUnit);
            aVar.m4959d(40L, timeUnit);
            aVar.m4958c(40L, timeUnit);
            File absoluteFile = downloadCacheDirectory.getAbsoluteFile();
            Intrinsics.checkNotNullExpressionValue(absoluteFile, "sdcache.absoluteFile");
            aVar.f11397k = new C4374d(absoluteFile, 10485760L);
            aVar.m4956a(c4480a);
            aVar.m4956a(new C0942c());
            bVar.m5695d(new C4375d0(aVar));
            return (InterfaceC0920d) bVar.m5694c().m5687b(InterfaceC0920d.class);
        }
    }

    /* renamed from: b.a.a.a.r.o.d$h */
    public static final class h extends Lambda implements Function0<Integer> {
        public h() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Integer invoke() {
            C0950d c0950d = C0950d.this;
            return Integer.valueOf(c0950d.m296d() >= c0950d.f529k ? c0950d.m296d() % c0950d.f529k == 0 ? (int) (c0950d.m296d() / c0950d.f529k) : 1 + ((int) (c0950d.m296d() / c0950d.f529k)) : 1);
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController$uploadFile$1", m5320f = "UploadVideoController.kt", m5321i = {0, 0, 0, 1, 1, 1, 2, 2}, m5322l = {94, 102, 104, 107}, m5323m = "invokeSuspend", m5324n = {"bufferByteArray", "fileInputStream", "bis", "bufferByteArray", "fileInputStream", "bis", "fileInputStream", "bis"}, m5325s = {"L$0", "L$1", "L$2", "L$0", "L$1", "L$2", "L$0", "L$1"})
    /* renamed from: b.a.a.a.r.o.d$i */
    public static final class i extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public Object f545c;

        /* renamed from: e */
        public Object f546e;

        /* renamed from: f */
        public Object f547f;

        /* renamed from: g */
        public int f548g;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController$uploadFile$1$1", m5320f = "UploadVideoController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.d$i$a */
        public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ C0950d f550c;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public a(C0950d c0950d, Continuation<? super a> continuation) {
                super(2, continuation);
                this.f550c = c0950d;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new a(this.f550c, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                return new a(this.f550c, continuation).invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                C0950d c0950d = this.f550c;
                a aVar = c0950d.f524f;
                if (aVar == null) {
                    return null;
                }
                aVar.onTotal(((Number) c0950d.f530l.getValue()).intValue());
                return Unit.INSTANCE;
            }
        }

        /* renamed from: b.a.a.a.r.o.d$i$b */
        public static final class b extends Lambda implements Function0<Integer> {

            /* renamed from: c */
            public final /* synthetic */ BufferedInputStream f551c;

            /* renamed from: e */
            public final /* synthetic */ Ref.ObjectRef<byte[]> f552e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(BufferedInputStream bufferedInputStream, Ref.ObjectRef<byte[]> objectRef) {
                super(0);
                this.f551c = bufferedInputStream;
                this.f552e = objectRef;
            }

            @Override // kotlin.jvm.functions.Function0
            public Integer invoke() {
                return Integer.valueOf(this.f551c.read(this.f552e.element));
            }
        }

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController$uploadFile$1$3", m5320f = "UploadVideoController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.d$i$c */
        public static final class c extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ C0950d f553c;

            /* renamed from: e */
            public final /* synthetic */ Exception f554e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public c(C0950d c0950d, Exception exc, Continuation<? super c> continuation) {
                super(2, continuation);
                this.f553c = c0950d;
                this.f554e = exc;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new c(this.f553c, this.f554e, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                C0950d c0950d = this.f553c;
                Exception exc = this.f554e;
                new c(c0950d, exc, continuation);
                Unit unit = Unit.INSTANCE;
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(unit);
                c0950d.f523e.invoke(exc.getMessage());
                return unit;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                this.f553c.f523e.invoke(this.f554e.getMessage());
                return Unit.INSTANCE;
            }
        }

        public i(Continuation<? super i> continuation) {
            super(2, continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return C0950d.this.new i(continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return C0950d.this.new i(continuation).invokeSuspend(Unit.INSTANCE);
        }

        /* JADX WARN: Removed duplicated region for block: B:29:0x012c A[RETURN] */
        /* JADX WARN: Removed duplicated region for block: B:30:0x012d  */
        /* JADX WARN: Type inference failed for: r14v6, types: [T, byte[]] */
        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r14) {
            /*
                Method dump skipped, instructions count: 320
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p022o.C0950d.i.invokeSuspend(java.lang.Object):java.lang.Object");
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C0950d(@NotNull String uploadBaseUrl, @NotNull String filePath, @NotNull String uploadToken, @NotNull Function1<? super UploadVideoResponse.DataBean, Unit> successBlock, @NotNull Function1<? super String, Unit> errorBlock) {
        Intrinsics.checkNotNullParameter(uploadBaseUrl, "uploadBaseUrl");
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        Intrinsics.checkNotNullParameter(uploadToken, "uploadToken");
        Intrinsics.checkNotNullParameter(successBlock, "successBlock");
        Intrinsics.checkNotNullParameter(errorBlock, "errorBlock");
        this.f519a = uploadBaseUrl;
        this.f520b = filePath;
        this.f521c = uploadToken;
        this.f522d = successBlock;
        this.f523e = errorBlock;
        this.f526h = LazyKt__LazyJVMKt.lazy(new g());
        this.f527i = LazyKt__LazyJVMKt.lazy(new d());
        this.f528j = LazyKt__LazyJVMKt.lazy(new e());
        this.f529k = 524288L;
        this.f530l = LazyKt__LazyJVMKt.lazy(new h());
        this.f532n = LazyKt__LazyJVMKt.lazy(new f());
    }

    /* renamed from: a */
    public static final File m293a(C0950d c0950d) {
        return (File) c0950d.f527i.getValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x012d  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x002f  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object m294b(p005b.p006a.p007a.p008a.p017r.p022o.C0950d r26, byte[] r27, kotlin.coroutines.Continuation r28) {
        /*
            Method dump skipped, instructions count: 313
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p022o.C0950d.m294b(b.a.a.a.r.o.d, byte[], kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0027  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object m295c(kotlin.coroutines.Continuation<? super kotlin.Unit> r11) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p022o.C0950d.m295c(kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* renamed from: d */
    public final long m296d() {
        return ((Number) this.f528j.getValue()).longValue();
    }

    @NotNull
    /* renamed from: e */
    public final InterfaceC3053d1 m297e() {
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        return C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new i(null), 2, null);
    }

    public final void setOnProgressListener(@Nullable a aVar) {
        this.f524f = aVar;
    }
}
