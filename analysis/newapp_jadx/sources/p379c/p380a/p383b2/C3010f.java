package p379c.p380a.p383b2;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.functions.Function3;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: c.a.b2.f */
/* loaded from: classes2.dex */
public final class C3010f<T> implements InterfaceC3006b<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8221a;

    /* renamed from: b */
    public final /* synthetic */ Function3 f8222b;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__ErrorsKt$catch$$inlined$unsafeFlow$1", m5320f = "Errors.kt", m5321i = {0, 0, 0, 0, 1, 1, 1, 1, 1}, m5322l = {113, 114}, m5323m = "collect", m5324n = {"this", "collector", "continuation", "$receiver", "this", "collector", "continuation", "$receiver", "exception"}, m5325s = {"L$0", "L$1", "L$2", "L$3", "L$0", "L$1", "L$2", "L$3", "L$4"})
    /* renamed from: c.a.b2.f$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8223c;

        /* renamed from: e */
        public int f8224e;

        /* renamed from: g */
        public Object f8226g;

        /* renamed from: h */
        public Object f8227h;

        /* renamed from: i */
        public Object f8228i;

        /* renamed from: j */
        public Object f8229j;

        /* renamed from: k */
        public Object f8230k;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8223c = obj;
            this.f8224e |= Integer.MIN_VALUE;
            return C3010f.this.mo289a(null, this);
        }
    }

    public C3010f(InterfaceC3006b interfaceC3006b, Function3 function3) {
        this.f8221a = interfaceC3006b;
        this.f8222b = function3;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @org.jetbrains.annotations.Nullable
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object mo289a(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c r8, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof p379c.p380a.p383b2.C3010f.a
            if (r0 == 0) goto L13
            r0 = r9
            c.a.b2.f$a r0 = (p379c.p380a.p383b2.C3010f.a) r0
            int r1 = r0.f8224e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8224e = r1
            goto L18
        L13:
            c.a.b2.f$a r0 = new c.a.b2.f$a
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.f8223c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8224e
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L5c
            if (r2 == r4) goto L48
            if (r2 != r3) goto L40
            java.lang.Object r8 = r0.f8230k
            java.lang.Throwable r8 = (java.lang.Throwable) r8
            java.lang.Object r8 = r0.f8229j
            c.a.b2.c r8 = (p379c.p380a.p383b2.InterfaceC3007c) r8
            java.lang.Object r8 = r0.f8228i
            kotlin.coroutines.Continuation r8 = (kotlin.coroutines.Continuation) r8
            java.lang.Object r8 = r0.f8227h
            c.a.b2.c r8 = (p379c.p380a.p383b2.InterfaceC3007c) r8
            java.lang.Object r8 = r0.f8226g
            c.a.b2.f r8 = (p379c.p380a.p383b2.C3010f) r8
            kotlin.ResultKt.throwOnFailure(r9)
            goto L96
        L40:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L48:
            java.lang.Object r8 = r0.f8229j
            c.a.b2.c r8 = (p379c.p380a.p383b2.InterfaceC3007c) r8
            java.lang.Object r2 = r0.f8228i
            kotlin.coroutines.Continuation r2 = (kotlin.coroutines.Continuation) r2
            java.lang.Object r4 = r0.f8227h
            c.a.b2.c r4 = (p379c.p380a.p383b2.InterfaceC3007c) r4
            java.lang.Object r5 = r0.f8226g
            c.a.b2.f r5 = (p379c.p380a.p383b2.C3010f) r5
            kotlin.ResultKt.throwOnFailure(r9)
            goto L75
        L5c:
            kotlin.ResultKt.throwOnFailure(r9)
            c.a.b2.b r9 = r7.f8221a
            r0.f8226g = r7
            r0.f8227h = r8
            r0.f8228i = r0
            r0.f8229j = r8
            r0.f8224e = r4
            java.lang.Object r9 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2521v(r9, r8, r0)
            if (r9 != r1) goto L72
            return r1
        L72:
            r5 = r7
            r4 = r8
            r2 = r0
        L75:
            java.lang.Throwable r9 = (java.lang.Throwable) r9
            if (r9 == 0) goto L96
            kotlin.jvm.functions.Function3 r6 = r5.f8222b
            r0.f8226g = r5
            r0.f8227h = r4
            r0.f8228i = r2
            r0.f8229j = r8
            r0.f8230k = r9
            r0.f8224e = r3
            r2 = 6
            kotlin.jvm.internal.InlineMarker.mark(r2)
            java.lang.Object r8 = r6.invoke(r8, r9, r0)
            r9 = 7
            kotlin.jvm.internal.InlineMarker.mark(r9)
            if (r8 != r1) goto L96
            return r1
        L96:
            kotlin.Unit r8 = kotlin.Unit.INSTANCE
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.C3010f.mo289a(c.a.b2.c, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
