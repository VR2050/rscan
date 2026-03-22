package p379c.p380a;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.t */
/* loaded from: classes2.dex */
public final class C3099t<T> extends C3068i1 implements InterfaceC3096s<T> {

    @DebugMetadata(m5319c = "kotlinx.coroutines.CompletableDeferredImpl", m5320f = "CompletableDeferred.kt", m5321i = {0}, m5322l = {86}, m5323m = "await", m5324n = {"this"}, m5325s = {"L$0"})
    /* renamed from: c.a.t$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8455c;

        /* renamed from: e */
        public int f8456e;

        /* renamed from: g */
        public Object f8458g;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8455c = obj;
            this.f8456e |= Integer.MIN_VALUE;
            return C3099t.this.mo3568s(this);
        }
    }

    public C3099t(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        super(true);
        m3578O(interfaceC3053d1);
    }

    @Override // p379c.p380a.InterfaceC3096s
    /* renamed from: D */
    public boolean mo3637D(@NotNull Throwable th) {
        return m3579R(new C3108w(th, false, 2));
    }

    @Override // p379c.p380a.InterfaceC3096s
    /* renamed from: E */
    public boolean mo3638E(T t) {
        return m3579R(t);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0035  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
    @Override // p379c.p380a.InterfaceC3067i0
    @org.jetbrains.annotations.Nullable
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object mo3568s(@org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super T> r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof p379c.p380a.C3099t.a
            if (r0 == 0) goto L13
            r0 = r6
            c.a.t$a r0 = (p379c.p380a.C3099t.a) r0
            int r1 = r0.f8456e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8456e = r1
            goto L18
        L13:
            c.a.t$a r0 = new c.a.t$a
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.f8455c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8456e
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.lang.Object r0 = r0.f8458g
            c.a.t r0 = (p379c.p380a.C3099t) r0
            kotlin.ResultKt.throwOnFailure(r6)
            goto L83
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L35:
            kotlin.ResultKt.throwOnFailure(r6)
            r0.f8458g = r5
            r0.f8456e = r3
        L3c:
            java.lang.Object r6 = r5.m3576L()
            boolean r2 = r6 instanceof p379c.p380a.InterfaceC3115y0
            if (r2 != 0) goto L52
            boolean r0 = r6 instanceof p379c.p380a.C3108w
            if (r0 != 0) goto L4d
            java.lang.Object r6 = p379c.p380a.C3071j1.m3618a(r6)
            goto L80
        L4d:
            c.a.w r6 = (p379c.p380a.C3108w) r6
            java.lang.Throwable r6 = r6.f8470b
            throw r6
        L52:
            int r6 = r5.m3585b0(r6)
            if (r6 < 0) goto L3c
            c.a.i1$a r6 = new c.a.i1$a
            kotlin.coroutines.Continuation r2 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.intercepted(r0)
            r6.<init>(r2, r5)
            c.a.r1 r2 = new c.a.r1
            r2.<init>(r5, r6)
            r4 = 0
            c.a.n0 r2 = r5.mo3552o(r4, r3, r2)
            c.a.o0 r3 = new c.a.o0
            r3.<init>(r2)
            r6.mo3562f(r3)
            java.lang.Object r6 = r6.m3612u()
            java.lang.Object r2 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            if (r6 != r2) goto L80
            kotlin.coroutines.jvm.internal.DebugProbesKt.probeCoroutineSuspended(r0)
        L80:
            if (r6 != r1) goto L83
            return r1
        L83:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.C3099t.mo3568s(kotlin.coroutines.Continuation):java.lang.Object");
    }
}
