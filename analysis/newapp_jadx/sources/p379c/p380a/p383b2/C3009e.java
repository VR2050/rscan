package p379c.p380a.p383b2;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: c.a.b2.e */
/* loaded from: classes2.dex */
public final class C3009e<T> implements InterfaceC3006b<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8211a;

    /* renamed from: b */
    public final /* synthetic */ Function2 f8212b;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__EmittersKt$onStart$$inlined$unsafeFlow$1", m5320f = "Emitters.kt", m5321i = {0, 0, 0, 0, 0, 1, 1, 1, 1, 1}, m5322l = {116, 120}, m5323m = "collect", m5324n = {"this", "collector", "continuation", "$receiver", "safeCollector", "this", "collector", "continuation", "$receiver", "safeCollector"}, m5325s = {"L$0", "L$1", "L$2", "L$3", "L$4", "L$0", "L$1", "L$2", "L$3", "L$4"})
    /* renamed from: c.a.b2.e$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8213c;

        /* renamed from: e */
        public int f8214e;

        /* renamed from: g */
        public Object f8216g;

        /* renamed from: h */
        public Object f8217h;

        /* renamed from: i */
        public Object f8218i;

        /* renamed from: j */
        public Object f8219j;

        /* renamed from: k */
        public Object f8220k;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8213c = obj;
            this.f8214e |= Integer.MIN_VALUE;
            return C3009e.this.mo289a(null, this);
        }
    }

    public C3009e(InterfaceC3006b interfaceC3006b, Function2 function2) {
        this.f8211a = interfaceC3006b;
        this.f8212b = function2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:21:0x00a7 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0062  */
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
            boolean r0 = r9 instanceof p379c.p380a.p383b2.C3009e.a
            if (r0 == 0) goto L13
            r0 = r9
            c.a.b2.e$a r0 = (p379c.p380a.p383b2.C3009e.a) r0
            int r1 = r0.f8214e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8214e = r1
            goto L18
        L13:
            c.a.b2.e$a r0 = new c.a.b2.e$a
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.f8213c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8214e
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L62
            if (r2 == r4) goto L48
            if (r2 != r3) goto L40
            java.lang.Object r8 = r0.f8220k
            c.a.b2.n.l r8 = (p379c.p380a.p383b2.p384n.C3029l) r8
            java.lang.Object r8 = r0.f8219j
            c.a.b2.c r8 = (p379c.p380a.p383b2.InterfaceC3007c) r8
            java.lang.Object r8 = r0.f8218i
            kotlin.coroutines.Continuation r8 = (kotlin.coroutines.Continuation) r8
            java.lang.Object r8 = r0.f8217h
            c.a.b2.c r8 = (p379c.p380a.p383b2.InterfaceC3007c) r8
            java.lang.Object r8 = r0.f8216g
            c.a.b2.e r8 = (p379c.p380a.p383b2.C3009e) r8
            kotlin.ResultKt.throwOnFailure(r9)
            goto La8
        L40:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L48:
            java.lang.Object r8 = r0.f8220k
            c.a.b2.n.l r8 = (p379c.p380a.p383b2.p384n.C3029l) r8
            java.lang.Object r2 = r0.f8219j
            c.a.b2.c r2 = (p379c.p380a.p383b2.InterfaceC3007c) r2
            java.lang.Object r4 = r0.f8218i
            kotlin.coroutines.Continuation r4 = (kotlin.coroutines.Continuation) r4
            java.lang.Object r5 = r0.f8217h
            c.a.b2.c r5 = (p379c.p380a.p383b2.InterfaceC3007c) r5
            java.lang.Object r6 = r0.f8216g
            c.a.b2.e r6 = (p379c.p380a.p383b2.C3009e) r6
            kotlin.ResultKt.throwOnFailure(r9)     // Catch: java.lang.Throwable -> L60
            goto L90
        L60:
            r9 = move-exception
            goto Lad
        L62:
            kotlin.ResultKt.throwOnFailure(r9)
            kotlin.coroutines.CoroutineContext r9 = r0.get$context()
            c.a.b2.n.l r2 = new c.a.b2.n.l
            r2.<init>(r8, r9)
            kotlin.jvm.functions.Function2 r9 = r7.f8212b     // Catch: java.lang.Throwable -> Lab
            r0.f8216g = r7     // Catch: java.lang.Throwable -> Lab
            r0.f8217h = r8     // Catch: java.lang.Throwable -> Lab
            r0.f8218i = r0     // Catch: java.lang.Throwable -> Lab
            r0.f8219j = r8     // Catch: java.lang.Throwable -> Lab
            r0.f8220k = r2     // Catch: java.lang.Throwable -> Lab
            r0.f8214e = r4     // Catch: java.lang.Throwable -> Lab
            r4 = 6
            kotlin.jvm.internal.InlineMarker.mark(r4)     // Catch: java.lang.Throwable -> Lab
            java.lang.Object r9 = r9.invoke(r2, r0)     // Catch: java.lang.Throwable -> Lab
            r4 = 7
            kotlin.jvm.internal.InlineMarker.mark(r4)     // Catch: java.lang.Throwable -> Lab
            if (r9 != r1) goto L8b
            return r1
        L8b:
            r6 = r7
            r5 = r8
            r4 = r0
            r8 = r2
            r2 = r5
        L90:
            r8.releaseIntercepted()
            c.a.b2.b r9 = r6.f8211a
            r0.f8216g = r6
            r0.f8217h = r5
            r0.f8218i = r4
            r0.f8219j = r2
            r0.f8220k = r8
            r0.f8214e = r3
            java.lang.Object r8 = r9.mo289a(r2, r0)
            if (r8 != r1) goto La8
            return r1
        La8:
            kotlin.Unit r8 = kotlin.Unit.INSTANCE
            return r8
        Lab:
            r9 = move-exception
            r8 = r2
        Lad:
            r8.releaseIntercepted()
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.C3009e.mo289a(c.a.b2.c, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
