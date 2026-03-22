package p005b.p006a.p007a.p008a.p017r.p022o;

import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.p022o.C0950d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;

/* renamed from: b.a.a.a.r.o.c */
/* loaded from: classes2.dex */
public final class C0949c {

    /* renamed from: a */
    @NotNull
    public final String f487a;

    /* renamed from: b */
    @NotNull
    public final String f488b;

    /* renamed from: c */
    @NotNull
    public final String f489c;

    /* renamed from: d */
    @NotNull
    public final Function1<String, Unit> f490d;

    /* renamed from: e */
    @NotNull
    public final String f491e;

    /* renamed from: f */
    @NotNull
    public final String f492f;

    /* renamed from: g */
    @Nullable
    public C0950d.a f493g;

    /* renamed from: h */
    @NotNull
    public final Lazy f494h;

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPic$1", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {64, 69}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: b.a.a.a.r.o.c$a */
    public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public int f495c;

        /* renamed from: e */
        public final /* synthetic */ Function1<UploadPicResponse.DataBean, Unit> f496e;

        /* renamed from: f */
        public final /* synthetic */ C0949c f497f;

        /* renamed from: g */
        public final /* synthetic */ String f498g;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPic$1$1", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {65}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.c$a$a, reason: collision with other inner class name */
        public static final class C5103a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public Object f499c;

            /* renamed from: e */
            public int f500e;

            /* renamed from: f */
            public final /* synthetic */ Function1<UploadPicResponse.DataBean, Unit> f501f;

            /* renamed from: g */
            public final /* synthetic */ C0949c f502g;

            /* renamed from: h */
            public final /* synthetic */ String f503h;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            public C5103a(Function1<? super UploadPicResponse.DataBean, Unit> function1, C0949c c0949c, String str, Continuation<? super C5103a> continuation) {
                super(2, continuation);
                this.f501f = function1;
                this.f502g = c0949c;
                this.f503h = str;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new C5103a(this.f501f, this.f502g, this.f503h, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                return new C5103a(this.f501f, this.f502g, this.f503h, continuation).invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                Function1 function1;
                Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                int i2 = this.f500e;
                if (i2 == 0) {
                    ResultKt.throwOnFailure(obj);
                    Function1<UploadPicResponse.DataBean, Unit> function12 = this.f501f;
                    C0949c c0949c = this.f502g;
                    String str = this.f503h;
                    this.f499c = function12;
                    this.f500e = 1;
                    Object m290a = C0949c.m290a(c0949c, str, this);
                    if (m290a == coroutine_suspended) {
                        return coroutine_suspended;
                    }
                    function1 = function12;
                    obj = m290a;
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    function1 = (Function1) this.f499c;
                    ResultKt.throwOnFailure(obj);
                }
                function1.invoke(obj);
                return Unit.INSTANCE;
            }
        }

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPic$1$2", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.c$a$b */
        public static final class b extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ C0949c f504c;

            /* renamed from: e */
            public final /* synthetic */ Exception f505e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(C0949c c0949c, Exception exc, Continuation<? super b> continuation) {
                super(2, continuation);
                this.f504c = c0949c;
                this.f505e = exc;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new b(this.f504c, this.f505e, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                C0949c c0949c = this.f504c;
                Exception exc = this.f505e;
                new b(c0949c, exc, continuation);
                Unit unit = Unit.INSTANCE;
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(unit);
                c0949c.f490d.invoke(exc.getMessage());
                return unit;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                this.f504c.f490d.invoke(this.f505e.getMessage());
                return Unit.INSTANCE;
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public a(Function1<? super UploadPicResponse.DataBean, Unit> function1, C0949c c0949c, String str, Continuation<? super a> continuation) {
            super(2, continuation);
            this.f496e = function1;
            this.f497f = c0949c;
            this.f498g = str;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new a(this.f496e, this.f497f, this.f498g, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return new a(this.f496e, this.f497f, this.f498g, continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.f495c;
            try {
            } catch (Exception e2) {
                e2.printStackTrace();
                C3079m0 c3079m0 = C3079m0.f8432c;
                AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
                b bVar = new b(this.f497f, e2, null);
                this.f495c = 2;
                if (C2354n.m2471e2(abstractC3077l1, bVar, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            }
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                C3079m0 c3079m02 = C3079m0.f8432c;
                AbstractC3077l1 abstractC3077l12 = C2964m.f8127b;
                C5103a c5103a = new C5103a(this.f496e, this.f497f, this.f498g, null);
                this.f495c = 1;
                if (C2354n.m2471e2(abstractC3077l12, c5103a, this) == coroutine_suspended) {
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
                ResultKt.throwOnFailure(obj);
            }
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPics$1", m5320f = "UploadPicController.kt", m5321i = {0, 0}, m5322l = {86, 89, 96}, m5323m = "invokeSuspend", m5324n = {"result", "index"}, m5325s = {"L$0", "L$1"})
    /* renamed from: b.a.a.a.r.o.c$b */
    public static final class b extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public Object f506c;

        /* renamed from: e */
        public Object f507e;

        /* renamed from: f */
        public Object f508f;

        /* renamed from: g */
        public int f509g;

        /* renamed from: h */
        public final /* synthetic */ List<String> f510h;

        /* renamed from: i */
        public final /* synthetic */ C0949c f511i;

        /* renamed from: j */
        public final /* synthetic */ Function1<ArrayList<UploadPicResponse.DataBean>, Unit> f512j;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPics$1$1", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.c$b$a */
        public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ Ref.IntRef f513c;

            /* renamed from: e */
            public final /* synthetic */ C0949c f514e;

            /* renamed from: f */
            public final /* synthetic */ Function1<ArrayList<UploadPicResponse.DataBean>, Unit> f515f;

            /* renamed from: g */
            public final /* synthetic */ ArrayList<UploadPicResponse.DataBean> f516g;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            public a(Ref.IntRef intRef, C0949c c0949c, Function1<? super ArrayList<UploadPicResponse.DataBean>, Unit> function1, ArrayList<UploadPicResponse.DataBean> arrayList, Continuation<? super a> continuation) {
                super(2, continuation);
                this.f513c = intRef;
                this.f514e = c0949c;
                this.f515f = function1;
                this.f516g = arrayList;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new a(this.f513c, this.f514e, this.f515f, this.f516g, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                return new a(this.f513c, this.f514e, this.f515f, this.f516g, continuation).invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                Ref.IntRef intRef = this.f513c;
                int i2 = intRef.element + 1;
                intRef.element = i2;
                C0950d.a aVar = this.f514e.f493g;
                if (aVar != null) {
                    aVar.onProgress(i2, "");
                }
                this.f515f.invoke(this.f516g);
                return Unit.INSTANCE;
            }
        }

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController$uploadPics$1$2", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.o.c$b$b, reason: collision with other inner class name */
        public static final class C5104b extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public final /* synthetic */ C0949c f517c;

            /* renamed from: e */
            public final /* synthetic */ Exception f518e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C5104b(C0949c c0949c, Exception exc, Continuation<? super C5104b> continuation) {
                super(2, continuation);
                this.f517c = c0949c;
                this.f518e = exc;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                return new C5104b(this.f517c, this.f518e, continuation);
            }

            @Override // kotlin.jvm.functions.Function2
            public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
                C0949c c0949c = this.f517c;
                Exception exc = this.f518e;
                new C5104b(c0949c, exc, continuation);
                Unit unit = Unit.INSTANCE;
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(unit);
                c0949c.f490d.invoke(exc.getMessage());
                return unit;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                ResultKt.throwOnFailure(obj);
                this.f517c.f490d.invoke(this.f518e.getMessage());
                return Unit.INSTANCE;
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public b(List<String> list, C0949c c0949c, Function1<? super ArrayList<UploadPicResponse.DataBean>, Unit> function1, Continuation<? super b> continuation) {
            super(2, continuation);
            this.f510h = list;
            this.f511i = c0949c;
            this.f512j = function1;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new b(this.f510h, this.f511i, this.f512j, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return new b(this.f510h, this.f511i, this.f512j, continuation).invokeSuspend(Unit.INSTANCE);
        }

        /* JADX WARN: Removed duplicated region for block: B:23:0x005a A[Catch: Exception -> 0x00a9, TRY_LEAVE, TryCatch #1 {Exception -> 0x00a9, blocks: (B:21:0x0054, B:23:0x005a, B:27:0x008b), top: B:20:0x0054 }] */
        /* JADX WARN: Removed duplicated region for block: B:27:0x008b A[Catch: Exception -> 0x00a9, TRY_ENTER, TRY_LEAVE, TryCatch #1 {Exception -> 0x00a9, blocks: (B:21:0x0054, B:23:0x005a, B:27:0x008b), top: B:20:0x0054 }] */
        /* JADX WARN: Removed duplicated region for block: B:35:0x00ce A[RETURN] */
        /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:26:0x0071 -> B:17:0x007a). Please report as a decompilation issue!!! */
        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r14) {
            /*
                Method dump skipped, instructions count: 210
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p022o.C0949c.b.invokeSuspend(java.lang.Object):java.lang.Object");
        }
    }

    public C0949c(String uploadBaseUrl, String uploadToken, String userId, Function1 errorBlock, String small, String compress, int i2) {
        small = (i2 & 16) != 0 ? "1" : small;
        compress = (i2 & 32) != 0 ? "" : compress;
        Intrinsics.checkNotNullParameter(uploadBaseUrl, "uploadBaseUrl");
        Intrinsics.checkNotNullParameter(uploadToken, "uploadToken");
        Intrinsics.checkNotNullParameter(userId, "userId");
        Intrinsics.checkNotNullParameter(errorBlock, "errorBlock");
        Intrinsics.checkNotNullParameter(small, "small");
        Intrinsics.checkNotNullParameter(compress, "compress");
        this.f487a = uploadBaseUrl;
        this.f488b = uploadToken;
        this.f489c = userId;
        this.f490d = errorBlock;
        this.f491e = small;
        this.f492f = compress;
        this.f494h = LazyKt__LazyJVMKt.lazy(new C0948b(this));
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x002d  */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object m290a(p005b.p006a.p007a.p008a.p017r.p022o.C0949c r18, java.lang.String r19, kotlin.coroutines.Continuation r20) {
        /*
            r0 = r18
            r7 = r19
            r1 = r20
            java.util.Objects.requireNonNull(r18)
            boolean r2 = r1 instanceof p005b.p006a.p007a.p008a.p017r.p022o.C0947a
            if (r2 == 0) goto L1c
            r2 = r1
            b.a.a.a.r.o.a r2 = (p005b.p006a.p007a.p008a.p017r.p022o.C0947a) r2
            int r3 = r2.f485f
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L1c
            int r3 = r3 - r4
            r2.f485f = r3
            goto L21
        L1c:
            b.a.a.a.r.o.a r2 = new b.a.a.a.r.o.a
            r2.<init>(r0, r1)
        L21:
            r8 = r2
            java.lang.Object r1 = r8.f483c
            java.lang.Object r9 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r8.f485f
            r10 = 1
            if (r2 == 0) goto L3b
            if (r2 != r10) goto L33
            kotlin.ResultKt.throwOnFailure(r1)
            goto L8f
        L33:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L3b:
            kotlin.ResultKt.throwOnFailure(r1)
            java.io.File r1 = new java.io.File
            r1.<init>(r7)
            k.b0$a r2 = p458k.C4371b0.f11309c
            java.lang.String r2 = "application/octet-stream"
            k.b0 r2 = p458k.C4371b0.a.m4946b(r2)
            java.lang.String r3 = "$this$asRequestBody"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r1, r3)
            k.h0 r15 = new k.h0
            r15.<init>(r1, r2)
            kotlin.Lazy r1 = r0.f494h
            java.lang.Object r1 = r1.getValue()
            r11 = r1
            b.a.a.a.r.d r11 = (p005b.p006a.p007a.p008a.p017r.InterfaceC0920d) r11
            java.lang.String r12 = r0.f488b
            java.lang.String r13 = r0.f489c
            r3 = 0
            r4 = 0
            r5 = 6
            r6 = 0
            java.lang.String r2 = "/"
            r1 = r19
            int r1 = kotlin.text.StringsKt__StringsKt.lastIndexOf$default(r1, r2, r3, r4, r5, r6)
            int r1 = r1 + r10
            java.lang.String r14 = r7.substring(r1)
            java.lang.String r1 = "this as java.lang.String).substring(startIndex)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r14, r1)
            java.lang.String r1 = r0.f491e
            java.lang.String r0 = r0.f492f
            r2 = r15
            r15 = r1
            r16 = r0
            r17 = r2
            c.a.i0 r0 = r11.m229c(r12, r13, r14, r15, r16, r17)
            r8.f485f = r10
            java.lang.Object r1 = r0.mo3568s(r8)
            if (r1 != r9) goto L8f
            goto Lb8
        L8f:
            com.jbzd.media.movecartoons.bean.UploadPicResponse r1 = (com.jbzd.media.movecartoons.bean.UploadPicResponse) r1
            java.lang.String r0 = r1.getStatus()
            if (r0 == 0) goto La0
            int r2 = r0.length()
            if (r2 != 0) goto L9e
            goto La0
        L9e:
            r2 = 0
            goto La1
        La0:
            r2 = 1
        La1:
            if (r2 != 0) goto Lac
            java.lang.String r2 = "y"
            boolean r0 = kotlin.jvm.internal.Intrinsics.areEqual(r0, r2)
            if (r0 == 0) goto Lac
            goto Lad
        Lac:
            r10 = 0
        Lad:
            if (r10 == 0) goto Lb9
            com.jbzd.media.movecartoons.bean.UploadPicResponse$DataBean r9 = r1.getData()
            java.lang.String r0 = "response.data"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r0)
        Lb8:
            return r9
        Lb9:
            b.a.a.a.r.l.a r0 = new b.a.a.a.r.l.a
            java.lang.String r1 = r1.getError()
            java.lang.String r2 = "response.error"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            r2 = -1
            java.lang.Integer r2 = kotlin.coroutines.jvm.internal.Boxing.boxInt(r2)
            r0.<init>(r1, r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p022o.C0949c.m290a(b.a.a.a.r.o.c, java.lang.String, kotlin.coroutines.Continuation):java.lang.Object");
    }

    @NotNull
    /* renamed from: b */
    public final InterfaceC3053d1 m291b(@NotNull String filePath, @NotNull Function1<? super UploadPicResponse.DataBean, Unit> successBlock) {
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        Intrinsics.checkNotNullParameter(successBlock, "successBlock");
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        return C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new a(successBlock, this, filePath, null), 2, null);
    }

    @NotNull
    /* renamed from: c */
    public final InterfaceC3053d1 m292c(@NotNull List<String> filePaths, @NotNull Function1<? super ArrayList<UploadPicResponse.DataBean>, Unit> successBlock) {
        Intrinsics.checkNotNullParameter(filePaths, "filePaths");
        Intrinsics.checkNotNullParameter(successBlock, "successBlock");
        C0950d.a aVar = this.f493g;
        if (aVar != null) {
            aVar.onTotal(filePaths.size());
        }
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        return C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new b(filePaths, this, successBlock, null), 2, null);
    }

    public final void setOnProgressListener(@Nullable C0950d.a aVar) {
        this.f493g = aVar;
    }
}
