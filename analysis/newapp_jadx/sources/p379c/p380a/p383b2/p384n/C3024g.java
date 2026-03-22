package p379c.p380a.p383b2.p384n;

import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.InterfaceC3102u;
import p379c.p380a.p382a2.InterfaceC2992o;
import p379c.p380a.p382a2.InterfaceC2994q;
import p379c.p380a.p382a2.InterfaceC2998u;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* JADX INFO: Add missing generic type declarations: [R] */
/* renamed from: c.a.b2.n.g */
/* loaded from: classes2.dex */
public final class C3024g<R> implements InterfaceC3006b<R> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8284a;

    /* renamed from: b */
    public final /* synthetic */ InterfaceC3006b f8285b;

    /* renamed from: c */
    public final /* synthetic */ Function3 f8286c;

    /* renamed from: c.a.b2.n.g$a */
    public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public InterfaceC3055e0 f8287c;

        /* renamed from: e */
        public Object f8288e;

        /* renamed from: f */
        public Object f8289f;

        /* renamed from: g */
        public Object f8290g;

        /* renamed from: h */
        public Object f8291h;

        /* renamed from: i */
        public Object f8292i;

        /* renamed from: j */
        public int f8293j;

        /* renamed from: k */
        public final /* synthetic */ InterfaceC3007c f8294k;

        /* renamed from: l */
        public final /* synthetic */ C3024g f8295l;

        /* renamed from: c.a.b2.n.g$a$a, reason: collision with other inner class name */
        public static final class C5118a extends SuspendLambda implements Function2<InterfaceC2992o<? super Object>, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public InterfaceC2992o f8296c;

            /* renamed from: e */
            public Object f8297e;

            /* renamed from: f */
            public Object f8298f;

            /* renamed from: g */
            public int f8299g;

            /* JADX INFO: Add missing generic type declarations: [T2] */
            /* renamed from: c.a.b2.n.g$a$a$a, reason: collision with other inner class name */
            public static final class C5119a<T2> implements InterfaceC3007c<T2> {

                /* renamed from: c */
                public final /* synthetic */ InterfaceC2992o f8301c;

                public C5119a(InterfaceC2992o interfaceC2992o) {
                    this.f8301c = interfaceC2992o;
                }

                @Override // p379c.p380a.p383b2.InterfaceC3007c
                @Nullable
                public Object emit(Object obj, @NotNull Continuation continuation) {
                    InterfaceC2998u mo3499k = this.f8301c.mo3499k();
                    if (obj == null) {
                        obj = C3028k.f8324a;
                    }
                    Object mo3484p = mo3499k.mo3484p(obj, continuation);
                    return mo3484p == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo3484p : Unit.INSTANCE;
                }
            }

            public C5118a(Continuation continuation) {
                super(2, continuation);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                C5118a c5118a = a.this.new C5118a(continuation);
                c5118a.f8296c = (InterfaceC2992o) obj;
                return c5118a;
            }

            @Override // kotlin.jvm.functions.Function2
            public final Object invoke(InterfaceC2992o<? super Object> interfaceC2992o, Continuation<? super Unit> continuation) {
                C5118a c5118a = a.this.new C5118a(continuation);
                c5118a.f8296c = interfaceC2992o;
                return c5118a.invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                int i2 = this.f8299g;
                if (i2 == 0) {
                    ResultKt.throwOnFailure(obj);
                    InterfaceC2992o interfaceC2992o = this.f8296c;
                    InterfaceC3006b interfaceC3006b = a.this.f8295l.f8284a;
                    C5119a c5119a = new C5119a(interfaceC2992o);
                    this.f8297e = interfaceC2992o;
                    this.f8298f = interfaceC3006b;
                    this.f8299g = 1;
                    if (interfaceC3006b.mo289a(c5119a, this) == coroutine_suspended) {
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

        /* renamed from: c.a.b2.n.g$a$b */
        public static final class b extends Lambda implements Function1<Throwable, Unit> {

            /* renamed from: e */
            public final /* synthetic */ InterfaceC3102u f8303e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(InterfaceC3102u interfaceC3102u) {
                super(1);
                this.f8303e = interfaceC3102u;
            }

            @Override // kotlin.jvm.functions.Function1
            public Unit invoke(Throwable th) {
                if (this.f8303e.mo3507b()) {
                    this.f8303e.mo3551d(new C3018a(a.this.f8294k));
                }
                return Unit.INSTANCE;
            }
        }

        /* renamed from: c.a.b2.n.g$a$c */
        public static final class c extends SuspendLambda implements Function2<Unit, Continuation<? super Unit>, Object> {

            /* renamed from: c */
            public Unit f8304c;

            /* renamed from: e */
            public Object f8305e;

            /* renamed from: f */
            public Object f8306f;

            /* renamed from: g */
            public int f8307g;

            /* renamed from: i */
            public final /* synthetic */ CoroutineContext f8309i;

            /* renamed from: j */
            public final /* synthetic */ Object f8310j;

            /* renamed from: k */
            public final /* synthetic */ InterfaceC2994q f8311k;

            /* JADX INFO: Add missing generic type declarations: [T1] */
            /* renamed from: c.a.b2.n.g$a$c$a, reason: collision with other inner class name */
            public static final class C5120a<T1> implements InterfaceC3007c<T1> {

                /* renamed from: c.a.b2.n.g$a$c$a$a, reason: collision with other inner class name */
                public static final class C5121a extends SuspendLambda implements Function2<Unit, Continuation<? super Unit>, Object> {

                    /* renamed from: c */
                    public Unit f8313c;

                    /* renamed from: e */
                    public Object f8314e;

                    /* renamed from: f */
                    public Object f8315f;

                    /* renamed from: g */
                    public Object f8316g;

                    /* renamed from: h */
                    public int f8317h;

                    /* renamed from: i */
                    public final /* synthetic */ Object f8318i;

                    /* renamed from: j */
                    public final /* synthetic */ C5120a f8319j;

                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    public C5121a(Object obj, Continuation continuation, C5120a c5120a) {
                        super(2, continuation);
                        this.f8318i = obj;
                        this.f8319j = c5120a;
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    @NotNull
                    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                        C5121a c5121a = new C5121a(this.f8318i, continuation, this.f8319j);
                        c5121a.f8313c = (Unit) obj;
                        return c5121a;
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public final Object invoke(Unit unit, Continuation<? super Unit> continuation) {
                        C5121a c5121a = new C5121a(this.f8318i, continuation, this.f8319j);
                        c5121a.f8313c = unit;
                        return c5121a.invokeSuspend(Unit.INSTANCE);
                    }

                    /* JADX WARN: Removed duplicated region for block: B:15:0x0099 A[RETURN] */
                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    @org.jetbrains.annotations.Nullable
                    /*
                        Code decompiled incorrectly, please refer to instructions dump.
                        To view partially-correct add '--show-bad-code' argument
                    */
                    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r9) {
                        /*
                            r8 = this;
                            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                            int r1 = r8.f8317h
                            r2 = 3
                            r3 = 2
                            r4 = 1
                            if (r1 == 0) goto L39
                            if (r1 == r4) goto L30
                            if (r1 == r3) goto L22
                            if (r1 != r2) goto L1a
                            java.lang.Object r0 = r8.f8314e
                            kotlin.Unit r0 = (kotlin.Unit) r0
                            kotlin.ResultKt.throwOnFailure(r9)
                            goto L9a
                        L1a:
                            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
                            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
                            r9.<init>(r0)
                            throw r9
                        L22:
                            java.lang.Object r1 = r8.f8316g
                            c.a.b2.c r1 = (p379c.p380a.p383b2.InterfaceC3007c) r1
                            java.lang.Object r3 = r8.f8315f
                            java.lang.Object r4 = r8.f8314e
                            kotlin.Unit r4 = (kotlin.Unit) r4
                            kotlin.ResultKt.throwOnFailure(r9)
                            goto L8d
                        L30:
                            java.lang.Object r1 = r8.f8314e
                            kotlin.Unit r1 = (kotlin.Unit) r1
                            kotlin.ResultKt.throwOnFailure(r9)
                            r4 = r1
                            goto L56
                        L39:
                            kotlin.ResultKt.throwOnFailure(r9)
                            kotlin.Unit r9 = r8.f8313c
                            c.a.b2.n.g$a$c$a r1 = r8.f8319j
                            c.a.b2.n.g$a$c r1 = p379c.p380a.p383b2.p384n.C3024g.a.c.this
                            c.a.a2.q r1 = r1.f8311k
                            r8.f8314e = r9
                            r8.f8317h = r4
                            java.lang.String r4 = "null cannot be cast to non-null type kotlinx.coroutines.channels.ReceiveChannel<E?>"
                            java.util.Objects.requireNonNull(r1, r4)
                            java.lang.Object r1 = r1.mo3459e(r8)
                            if (r1 != r0) goto L54
                            return r0
                        L54:
                            r4 = r9
                            r9 = r1
                        L56:
                            if (r9 == 0) goto L9d
                            c.a.b2.n.g$a$c$a r1 = r8.f8319j
                            c.a.b2.n.g$a$c r1 = p379c.p380a.p383b2.p384n.C3024g.a.c.this
                            c.a.b2.n.g$a r1 = p379c.p380a.p383b2.p384n.C3024g.a.this
                            c.a.b2.c r5 = r1.f8294k
                            c.a.b2.n.g r1 = r1.f8295l
                            kotlin.jvm.functions.Function3 r1 = r1.f8286c
                            java.lang.Object r6 = r8.f8318i
                            c.a.a.s r7 = p379c.p380a.p383b2.p384n.C3028k.f8324a
                            if (r9 != r7) goto L6c
                            r7 = 0
                            goto L6d
                        L6c:
                            r7 = r9
                        L6d:
                            r8.f8314e = r4
                            r8.f8315f = r9
                            r8.f8316g = r5
                            r8.f8317h = r3
                            r3 = 6
                            kotlin.jvm.internal.InlineMarker.mark(r3)
                            kotlin.jvm.internal.InlineMarker.mark(r3)
                            java.lang.Object r1 = r1.invoke(r6, r7, r8)
                            r3 = 7
                            kotlin.jvm.internal.InlineMarker.mark(r3)
                            kotlin.jvm.internal.InlineMarker.mark(r3)
                            if (r1 != r0) goto L8a
                            return r0
                        L8a:
                            r3 = r9
                            r9 = r1
                            r1 = r5
                        L8d:
                            r8.f8314e = r4
                            r8.f8315f = r3
                            r8.f8317h = r2
                            java.lang.Object r9 = r1.emit(r9, r8)
                            if (r9 != r0) goto L9a
                            return r0
                        L9a:
                            kotlin.Unit r9 = kotlin.Unit.INSTANCE
                            return r9
                        L9d:
                            c.a.b2.n.a r9 = new c.a.b2.n.a
                            c.a.b2.n.g$a$c$a r0 = r8.f8319j
                            c.a.b2.n.g$a$c r0 = p379c.p380a.p383b2.p384n.C3024g.a.c.this
                            c.a.b2.n.g$a r0 = p379c.p380a.p383b2.p384n.C3024g.a.this
                            c.a.b2.c r0 = r0.f8294k
                            r9.<init>(r0)
                            throw r9
                        */
                        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.p384n.C3024g.a.c.C5120a.C5121a.invokeSuspend(java.lang.Object):java.lang.Object");
                    }
                }

                public C5120a() {
                }

                @Override // p379c.p380a.p383b2.InterfaceC3007c
                @Nullable
                public Object emit(Object obj, @NotNull Continuation continuation) {
                    c cVar = c.this;
                    CoroutineContext coroutineContext = cVar.f8309i;
                    Unit unit = Unit.INSTANCE;
                    Object m2475f2 = C2354n.m2475f2(coroutineContext, unit, cVar.f8310j, new C5121a(obj, null, this), continuation);
                    return m2475f2 == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m2475f2 : unit;
                }
            }

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public c(CoroutineContext coroutineContext, Object obj, InterfaceC2994q interfaceC2994q, Continuation continuation) {
                super(2, continuation);
                this.f8309i = coroutineContext;
                this.f8310j = obj;
                this.f8311k = interfaceC2994q;
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @NotNull
            public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                c cVar = a.this.new c(this.f8309i, this.f8310j, this.f8311k, continuation);
                cVar.f8304c = (Unit) obj;
                return cVar;
            }

            @Override // kotlin.jvm.functions.Function2
            public final Object invoke(Unit unit, Continuation<? super Unit> continuation) {
                return ((c) create(unit, continuation)).invokeSuspend(Unit.INSTANCE);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                int i2 = this.f8307g;
                if (i2 == 0) {
                    ResultKt.throwOnFailure(obj);
                    Unit unit = this.f8304c;
                    InterfaceC3006b interfaceC3006b = a.this.f8295l.f8285b;
                    C5120a c5120a = new C5120a();
                    this.f8305e = unit;
                    this.f8306f = interfaceC3006b;
                    this.f8307g = 1;
                    if (interfaceC3006b.mo289a(c5120a, this) == coroutine_suspended) {
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

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(InterfaceC3007c interfaceC3007c, Continuation continuation, C3024g c3024g) {
            super(2, continuation);
            this.f8294k = interfaceC3007c;
            this.f8295l = c3024g;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            a aVar = new a(this.f8294k, continuation, this.f8295l);
            aVar.f8287c = (InterfaceC3055e0) obj;
            return aVar;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            a aVar = new a(this.f8294k, continuation, this.f8295l);
            aVar.f8287c = interfaceC3055e0;
            return aVar.invokeSuspend(Unit.INSTANCE);
        }

        /* JADX WARN: Code restructure failed: missing block: B:11:0x00af, code lost:
        
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2515t(r1, null, 1, null);
         */
        /* JADX WARN: Code restructure failed: missing block: B:13:0x00b4, code lost:
        
            return kotlin.Unit.INSTANCE;
         */
        /* JADX WARN: Code restructure failed: missing block: B:20:0x00ac, code lost:
        
            if (r1.mo3457c() == false) goto L21;
         */
        /* JADX WARN: Code restructure failed: missing block: B:9:0x0099, code lost:
        
            if (r1.mo3457c() == false) goto L21;
         */
        /* JADX WARN: Removed duplicated region for block: B:19:0x00a8  */
        /* JADX WARN: Removed duplicated region for block: B:21:0x00b5 A[Catch: all -> 0x0024, TRY_ENTER, TRY_LEAVE, TryCatch #1 {all -> 0x0024, blocks: (B:7:0x001f, B:17:0x00a2, B:21:0x00b5), top: B:2:0x000a }] */
        /* JADX WARN: Type inference failed for: r1v0, types: [int] */
        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r18) {
            /*
                r17 = this;
                r7 = r17
                java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                int r1 = r7.f8293j
                r8 = 0
                r9 = 1
                if (r1 == 0) goto L32
                if (r1 != r9) goto L2a
                java.lang.Object r0 = r7.f8291h
                kotlin.coroutines.CoroutineContext r0 = (kotlin.coroutines.CoroutineContext) r0
                java.lang.Object r0 = r7.f8290g
                c.a.u r0 = (p379c.p380a.InterfaceC3102u) r0
                java.lang.Object r0 = r7.f8289f
                r1 = r0
                c.a.a2.q r1 = (p379c.p380a.p382a2.InterfaceC2994q) r1
                java.lang.Object r0 = r7.f8288e
                c.a.e0 r0 = (p379c.p380a.InterfaceC3055e0) r0
                kotlin.ResultKt.throwOnFailure(r18)     // Catch: java.lang.Throwable -> L24 p379c.p380a.p383b2.p384n.C3018a -> L27
                goto L95
            L24:
                r0 = move-exception
                goto Lb6
            L27:
                r0 = move-exception
                goto La2
            L2a:
                java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
                java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
                r0.<init>(r1)
                throw r0
            L32:
                kotlin.ResultKt.throwOnFailure(r18)
                c.a.e0 r6 = r7.f8287c
                c.a.b2.n.g$a$a r1 = new c.a.b2.n.g$a$a
                r1.<init>(r8)
                kotlin.coroutines.EmptyCoroutineContext r11 = kotlin.coroutines.EmptyCoroutineContext.INSTANCE
                r12 = 0
                c.a.a2.e r13 = p379c.p380a.p382a2.EnumC2982e.SUSPEND
                r14 = 1
                r15 = 0
                r10 = r6
                r16 = r1
                c.a.a2.q r10 = p379c.p380a.p382a2.C2990m.m3496a(r10, r11, r12, r13, r14, r15, r16)
                c.a.u r11 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2460c(r8, r9, r8)
                r1 = r10
                c.a.a2.u r1 = (p379c.p380a.p382a2.InterfaceC2998u) r1
                c.a.b2.n.g$a$b r2 = new c.a.b2.n.g$a$b
                r2.<init>(r11)
                r1.mo3482m(r2)
                kotlin.coroutines.CoroutineContext r12 = r6.getCoroutineContext()     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                java.lang.Object r13 = p379c.p380a.p381a.C2952a.m3413b(r12)     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                kotlin.coroutines.CoroutineContext r1 = r6.getCoroutineContext()     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                kotlin.coroutines.CoroutineContext r14 = r1.plus(r11)     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                kotlin.Unit r15 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                c.a.b2.n.g$a$c r5 = new c.a.b2.n.g$a$c     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r16 = 0
                r1 = r5
                r2 = r17
                r3 = r12
                r4 = r13
                r8 = r5
                r5 = r10
                r9 = r6
                r6 = r16
                r1.<init>(r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r7.f8288e = r9     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r7.f8289f = r10     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r7.f8290g = r11     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r7.f8291h = r12     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r7.f8292i = r13     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                r1 = 1
                r7.f8293j = r1     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                java.lang.Object r1 = p379c.p380a.p381a.C2952a.m3413b(r14)     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                java.lang.Object r1 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2475f2(r14, r15, r1, r8, r7)     // Catch: java.lang.Throwable -> L9e p379c.p380a.p383b2.p384n.C3018a -> La0
                if (r1 != r0) goto L94
                return r0
            L94:
                r1 = r10
            L95:
                boolean r0 = r1.mo3457c()
                if (r0 != 0) goto Lb2
            L9b:
                r2 = 0
                r3 = 1
                goto Laf
            L9e:
                r0 = move-exception
                goto Lb7
            La0:
                r0 = move-exception
                r1 = r10
            La2:
                c.a.b2.c r2 = r7.f8294k     // Catch: java.lang.Throwable -> L24
                c.a.b2.c<?> r3 = r0.f8266c     // Catch: java.lang.Throwable -> L24
                if (r3 != r2) goto Lb5
                boolean r0 = r1.mo3457c()
                if (r0 != 0) goto Lb2
                goto L9b
            Laf:
                p005b.p199l.p200a.p201a.p250p1.C2354n.m2515t(r1, r2, r3, r2)
            Lb2:
                kotlin.Unit r0 = kotlin.Unit.INSTANCE
                return r0
            Lb5:
                throw r0     // Catch: java.lang.Throwable -> L24
            Lb6:
                r10 = r1
            Lb7:
                boolean r1 = r10.mo3457c()
                if (r1 != 0) goto Lc2
                r1 = 0
                r2 = 1
                p005b.p199l.p200a.p201a.p250p1.C2354n.m2515t(r10, r1, r2, r1)
            Lc2:
                throw r0
            */
            throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.p384n.C3024g.a.invokeSuspend(java.lang.Object):java.lang.Object");
        }
    }

    public C3024g(InterfaceC3006b interfaceC3006b, InterfaceC3006b interfaceC3006b2, Function3 function3) {
        this.f8284a = interfaceC3006b;
        this.f8285b = interfaceC3006b2;
        this.f8286c = function3;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c interfaceC3007c, @NotNull Continuation continuation) {
        Object m2401J = C2354n.m2401J(new a(interfaceC3007c, null, this), continuation);
        return m2401J == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m2401J : Unit.INSTANCE;
    }
}
