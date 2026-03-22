package p379c.p380a.p383b2;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.functions.Function3;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: c.a.b2.d */
/* loaded from: classes2.dex */
public final class C3008d<T> implements InterfaceC3006b<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8201a;

    /* renamed from: b */
    public final /* synthetic */ Function3 f8202b;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1", m5320f = "Emitters.kt", m5321i = {0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2}, m5322l = {114, 121, 128}, m5323m = "collect", m5324n = {"this", "collector", "continuation", "$receiver", "this", "collector", "continuation", "$receiver", C1568e.f1949a, "this", "collector", "continuation", "$receiver", "sc"}, m5325s = {"L$0", "L$1", "L$2", "L$3", "L$0", "L$1", "L$2", "L$3", "L$4", "L$0", "L$1", "L$2", "L$3", "L$4"})
    /* renamed from: c.a.b2.d$a */
    public static final class a extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f8203c;

        /* renamed from: e */
        public int f8204e;

        /* renamed from: g */
        public Object f8206g;

        /* renamed from: h */
        public Object f8207h;

        /* renamed from: i */
        public Object f8208i;

        /* renamed from: j */
        public Object f8209j;

        /* renamed from: k */
        public Object f8210k;

        public a(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f8203c = obj;
            this.f8204e |= Integer.MIN_VALUE;
            return C3008d.this.mo289a(null, this);
        }
    }

    public C3008d(InterfaceC3006b interfaceC3006b, Function3 function3) {
        this.f8201a = interfaceC3006b;
        this.f8202b = function3;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x00c0 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00ed A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:43:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0025  */
    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @org.jetbrains.annotations.Nullable
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object mo289a(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c r10, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r11) {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.C3008d.mo289a(c.a.b2.c, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
