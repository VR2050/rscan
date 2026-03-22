package p379c.p380a.p383b2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.b2.a */
/* loaded from: classes2.dex */
public abstract class AbstractC3005a<T> implements InterfaceC3006b<T> {

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.AbstractFlow", m5320f = "Flow.kt", m5321i = {0, 0, 0}, m5322l = {212}, m5323m = "collect", m5324n = {"this", "collector", "safeCollector"}, m5325s = {"L$0", "L$1", "L$2"})
    /* renamed from: c.a.b2.a$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8195c;

        /* renamed from: e */
        public int f8196e;

        /* renamed from: g */
        public Object f8198g;

        /* renamed from: h */
        public Object f8199h;

        /* renamed from: i */
        public Object f8200i;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8195c = obj;
            this.f8196e |= Integer.MIN_VALUE;
            return AbstractC3005a.this.mo289a(null, this);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @org.jetbrains.annotations.Nullable
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object mo289a(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c<? super T> r6, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super kotlin.Unit> r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof p379c.p380a.p383b2.AbstractC3005a.a
            if (r0 == 0) goto L13
            r0 = r7
            c.a.b2.a$a r0 = (p379c.p380a.p383b2.AbstractC3005a.a) r0
            int r1 = r0.f8196e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8196e = r1
            goto L18
        L13:
            c.a.b2.a$a r0 = new c.a.b2.a$a
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.f8195c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8196e
            r3 = 1
            if (r2 == 0) goto L3f
            if (r2 != r3) goto L37
            java.lang.Object r6 = r0.f8200i
            c.a.b2.n.l r6 = (p379c.p380a.p383b2.p384n.C3029l) r6
            java.lang.Object r1 = r0.f8199h
            c.a.b2.c r1 = (p379c.p380a.p383b2.InterfaceC3007c) r1
            java.lang.Object r0 = r0.f8198g
            c.a.b2.a r0 = (p379c.p380a.p383b2.AbstractC3005a) r0
            kotlin.ResultKt.throwOnFailure(r7)     // Catch: java.lang.Throwable -> L35
            goto L5b
        L35:
            r7 = move-exception
            goto L65
        L37:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L3f:
            kotlin.ResultKt.throwOnFailure(r7)
            c.a.b2.n.l r7 = new c.a.b2.n.l
            kotlin.coroutines.CoroutineContext r2 = r0.getContext()
            r7.<init>(r6, r2)
            r0.f8198g = r5     // Catch: java.lang.Throwable -> L61
            r0.f8199h = r6     // Catch: java.lang.Throwable -> L61
            r0.f8200i = r7     // Catch: java.lang.Throwable -> L61
            r0.f8196e = r3     // Catch: java.lang.Throwable -> L61
            java.lang.Object r6 = r5.mo3515c(r7, r0)     // Catch: java.lang.Throwable -> L61
            if (r6 != r1) goto L5a
            return r1
        L5a:
            r6 = r7
        L5b:
            r6.releaseIntercepted()
            kotlin.Unit r6 = kotlin.Unit.INSTANCE
            return r6
        L61:
            r6 = move-exception
            r4 = r7
            r7 = r6
            r6 = r4
        L65:
            r6.releaseIntercepted()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.AbstractC3005a.mo289a(c.a.b2.c, kotlin.coroutines.Continuation):java.lang.Object");
    }

    @Nullable
    /* renamed from: c */
    public abstract Object mo3515c(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation);
}
