package p379c.p380a.p383b2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* JADX INFO: Add missing generic type declarations: [R] */
/* renamed from: c.a.b2.i */
/* loaded from: classes2.dex */
public final class C3013i<R> implements InterfaceC3006b<InterfaceC3006b<? extends R>> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8246a;

    /* renamed from: b */
    public final /* synthetic */ Function2 f8247b;

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: c.a.b2.i$a */
    public static final class a<T> implements InterfaceC3007c<T> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC3007c f8248c;

        /* renamed from: e */
        public final /* synthetic */ C3013i f8249e;

        @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__MergeKt$flatMapConcat$$inlined$map$1$2", m5320f = "Merge.kt", m5321i = {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1}, m5322l = {134, 134}, m5323m = "emit", m5324n = {"this", "value", "continuation", "value", "continuation", "value", "$receiver", "this", "value", "continuation", "value", "continuation", "value", "$receiver"}, m5325s = {"L$0", "L$1", "L$2", "L$3", "L$4", "L$5", "L$6", "L$0", "L$1", "L$2", "L$3", "L$4", "L$5", "L$6"})
        /* renamed from: c.a.b2.i$a$a, reason: collision with other inner class name */
        public static final class C5117a extends ContinuationImpl {

            /* renamed from: c */
            public /* synthetic */ Object f8250c;

            /* renamed from: e */
            public int f8251e;

            /* renamed from: f */
            public Object f8252f;

            /* renamed from: g */
            public Object f8253g;

            /* renamed from: h */
            public Object f8254h;

            /* renamed from: i */
            public Object f8255i;

            /* renamed from: j */
            public Object f8256j;

            /* renamed from: k */
            public Object f8257k;

            /* renamed from: l */
            public Object f8258l;

            /* renamed from: m */
            public Object f8259m;

            public C5117a(Continuation continuation) {
                super(continuation);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                this.f8250c = obj;
                this.f8251e |= Integer.MIN_VALUE;
                return a.this.emit(null, this);
            }
        }

        public a(InterfaceC3007c interfaceC3007c, C3013i c3013i) {
            this.f8248c = interfaceC3007c;
            this.f8249e = c3013i;
        }

        /* JADX WARN: Removed duplicated region for block: B:19:0x00a4 A[RETURN] */
        /* JADX WARN: Removed duplicated region for block: B:20:0x0063  */
        /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Object emit(java.lang.Object r11, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r12) {
            /*
                r10 = this;
                boolean r0 = r12 instanceof p379c.p380a.p383b2.C3013i.a.C5117a
                if (r0 == 0) goto L13
                r0 = r12
                c.a.b2.i$a$a r0 = (p379c.p380a.p383b2.C3013i.a.C5117a) r0
                int r1 = r0.f8251e
                r2 = -2147483648(0xffffffff80000000, float:-0.0)
                r3 = r1 & r2
                if (r3 == 0) goto L13
                int r1 = r1 - r2
                r0.f8251e = r1
                goto L18
            L13:
                c.a.b2.i$a$a r0 = new c.a.b2.i$a$a
                r0.<init>(r12)
            L18:
                java.lang.Object r12 = r0.f8250c
                java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                int r2 = r0.f8251e
                r3 = 2
                r4 = 1
                if (r2 == 0) goto L63
                if (r2 == r4) goto L45
                if (r2 != r3) goto L3d
                java.lang.Object r11 = r0.f8258l
                c.a.b2.c r11 = (p379c.p380a.p383b2.InterfaceC3007c) r11
                java.lang.Object r11 = r0.f8256j
                c.a.b2.i$a$a r11 = (p379c.p380a.p383b2.C3013i.a.C5117a) r11
                java.lang.Object r11 = r0.f8254h
                c.a.b2.i$a$a r11 = (p379c.p380a.p383b2.C3013i.a.C5117a) r11
                java.lang.Object r11 = r0.f8252f
                c.a.b2.i$a r11 = (p379c.p380a.p383b2.C3013i.a) r11
                kotlin.ResultKt.throwOnFailure(r12)
                goto La5
            L3d:
                java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
                java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
                r11.<init>(r12)
                throw r11
            L45:
                java.lang.Object r11 = r0.f8259m
                c.a.b2.c r11 = (p379c.p380a.p383b2.InterfaceC3007c) r11
                java.lang.Object r2 = r0.f8258l
                c.a.b2.c r2 = (p379c.p380a.p383b2.InterfaceC3007c) r2
                java.lang.Object r4 = r0.f8257k
                java.lang.Object r5 = r0.f8256j
                c.a.b2.i$a$a r5 = (p379c.p380a.p383b2.C3013i.a.C5117a) r5
                java.lang.Object r6 = r0.f8255i
                java.lang.Object r7 = r0.f8254h
                c.a.b2.i$a$a r7 = (p379c.p380a.p383b2.C3013i.a.C5117a) r7
                java.lang.Object r8 = r0.f8253g
                java.lang.Object r9 = r0.f8252f
                c.a.b2.i$a r9 = (p379c.p380a.p383b2.C3013i.a) r9
                kotlin.ResultKt.throwOnFailure(r12)
                goto L8e
            L63:
                kotlin.ResultKt.throwOnFailure(r12)
                c.a.b2.c r12 = r10.f8248c
                c.a.b2.i r2 = r10.f8249e
                kotlin.jvm.functions.Function2 r2 = r2.f8247b
                r0.f8252f = r10
                r0.f8253g = r11
                r0.f8254h = r0
                r0.f8255i = r11
                r0.f8256j = r0
                r0.f8257k = r11
                r0.f8258l = r12
                r0.f8259m = r12
                r0.f8251e = r4
                java.lang.Object r2 = r2.invoke(r11, r0)
                if (r2 != r1) goto L85
                return r1
            L85:
                r9 = r10
                r4 = r11
                r6 = r4
                r8 = r6
                r11 = r12
                r5 = r0
                r7 = r5
                r12 = r2
                r2 = r11
            L8e:
                r0.f8252f = r9
                r0.f8253g = r8
                r0.f8254h = r7
                r0.f8255i = r6
                r0.f8256j = r5
                r0.f8257k = r4
                r0.f8258l = r2
                r0.f8251e = r3
                java.lang.Object r11 = r11.emit(r12, r0)
                if (r11 != r1) goto La5
                return r1
            La5:
                kotlin.Unit r11 = kotlin.Unit.INSTANCE
                return r11
            */
            throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.C3013i.a.emit(java.lang.Object, kotlin.coroutines.Continuation):java.lang.Object");
        }
    }

    public C3013i(InterfaceC3006b interfaceC3006b, Function2 function2) {
        this.f8246a = interfaceC3006b;
        this.f8247b = function2;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c interfaceC3007c, @NotNull Continuation continuation) {
        Object mo289a = this.f8246a.mo289a(new a(interfaceC3007c, this), continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }
}
