package p379c.p380a.p383b2;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.internal.Ref;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: c.a.b2.g */
/* loaded from: classes2.dex */
public final class C3011g<T> implements InterfaceC3007c<T> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC3007c f8231c;

    /* renamed from: e */
    public final /* synthetic */ Ref.ObjectRef f8232e;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__ErrorsKt$catchImpl$$inlined$collect$1", m5320f = "Errors.kt", m5321i = {0, 0, 0, 0}, m5322l = {134}, m5323m = "emit", m5324n = {"this", "value", "continuation", "it"}, m5325s = {"L$0", "L$1", "L$2", "L$3"})
    /* renamed from: c.a.b2.g$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8233c;

        /* renamed from: e */
        public int f8234e;

        /* renamed from: g */
        public Object f8236g;

        /* renamed from: h */
        public Object f8237h;

        /* renamed from: i */
        public Object f8238i;

        /* renamed from: j */
        public Object f8239j;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8233c = obj;
            this.f8234e |= Integer.MIN_VALUE;
            return C3011g.this.emit(null, this);
        }
    }

    public C3011g(InterfaceC3007c interfaceC3007c, Ref.ObjectRef objectRef) {
        this.f8231c = interfaceC3007c;
        this.f8232e = objectRef;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
    @Override // p379c.p380a.p383b2.InterfaceC3007c
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object emit(java.lang.Object r5, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof p379c.p380a.p383b2.C3011g.a
            if (r0 == 0) goto L13
            r0 = r6
            c.a.b2.g$a r0 = (p379c.p380a.p383b2.C3011g.a) r0
            int r1 = r0.f8234e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8234e = r1
            goto L18
        L13:
            c.a.b2.g$a r0 = new c.a.b2.g$a
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.f8233c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8234e
            r3 = 1
            if (r2 == 0) goto L3b
            if (r2 != r3) goto L33
            java.lang.Object r5 = r0.f8238i
            kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
            java.lang.Object r5 = r0.f8236g
            c.a.b2.g r5 = (p379c.p380a.p383b2.C3011g) r5
            kotlin.ResultKt.throwOnFailure(r6)     // Catch: java.lang.Throwable -> L31
            goto L51
        L31:
            r6 = move-exception
            goto L56
        L33:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L3b:
            kotlin.ResultKt.throwOnFailure(r6)
            c.a.b2.c r6 = r4.f8231c     // Catch: java.lang.Throwable -> L54
            r0.f8236g = r4     // Catch: java.lang.Throwable -> L54
            r0.f8237h = r5     // Catch: java.lang.Throwable -> L54
            r0.f8238i = r0     // Catch: java.lang.Throwable -> L54
            r0.f8239j = r5     // Catch: java.lang.Throwable -> L54
            r0.f8234e = r3     // Catch: java.lang.Throwable -> L54
            java.lang.Object r5 = r6.emit(r5, r0)     // Catch: java.lang.Throwable -> L54
            if (r5 != r1) goto L51
            return r1
        L51:
            kotlin.Unit r5 = kotlin.Unit.INSTANCE
            return r5
        L54:
            r6 = move-exception
            r5 = r4
        L56:
            kotlin.jvm.internal.Ref$ObjectRef r5 = r5.f8232e
            r5.element = r6
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.C3011g.emit(java.lang.Object, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
