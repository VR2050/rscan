package p005b.p006a.p007a.p008a.p009a;

import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.utils.DownloadRunnable$downLoadWork$1", m5320f = "VideoDownloadController.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.a.m */
/* loaded from: classes2.dex */
public final class C0858m extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public final /* synthetic */ DownloadVideoInfo f285c;

    /* renamed from: e */
    public final /* synthetic */ RunnableC0860n f286e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0858m(DownloadVideoInfo downloadVideoInfo, RunnableC0860n runnableC0860n, Continuation<? super C0858m> continuation) {
        super(2, continuation);
        this.f285c = downloadVideoInfo;
        this.f286e = runnableC0860n;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C0858m(this.f285c, this.f286e, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C0858m(this.f285c, this.f286e, continuation).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x00a1 A[Catch: all -> 0x029a, Exception -> 0x029c, TryCatch #2 {Exception -> 0x029c, blocks: (B:4:0x0012, B:6:0x0027, B:7:0x002a, B:9:0x004f, B:10:0x0073, B:12:0x007b, B:16:0x0087, B:18:0x008c, B:19:0x0091, B:21:0x0095, B:26:0x00a1, B:28:0x00de, B:29:0x00ea, B:31:0x00f2, B:33:0x00fe, B:35:0x0136, B:36:0x0139, B:58:0x0262, B:63:0x0273, B:64:0x0270, B:65:0x026a), top: B:3:0x0012, outer: #7 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0292 A[LOOP:0: B:31:0x00f2->B:53:0x0292, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x02a0 A[EDGE_INSN: B:54:0x02a0->B:120:0x02a0 BREAK  A[LOOP:0: B:31:0x00f2->B:53:0x0292], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0269  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x026f  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0270 A[Catch: all -> 0x029a, Exception -> 0x029c, TryCatch #2 {Exception -> 0x029c, blocks: (B:4:0x0012, B:6:0x0027, B:7:0x002a, B:9:0x004f, B:10:0x0073, B:12:0x007b, B:16:0x0087, B:18:0x008c, B:19:0x0091, B:21:0x0095, B:26:0x00a1, B:28:0x00de, B:29:0x00ea, B:31:0x00f2, B:33:0x00fe, B:35:0x0136, B:36:0x0139, B:58:0x0262, B:63:0x0273, B:64:0x0270, B:65:0x026a), top: B:3:0x0012, outer: #7 }] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x026a A[Catch: all -> 0x029a, Exception -> 0x029c, TryCatch #2 {Exception -> 0x029c, blocks: (B:4:0x0012, B:6:0x0027, B:7:0x002a, B:9:0x004f, B:10:0x0073, B:12:0x007b, B:16:0x0087, B:18:0x008c, B:19:0x0091, B:21:0x0095, B:26:0x00a1, B:28:0x00de, B:29:0x00ea, B:31:0x00f2, B:33:0x00fe, B:35:0x0136, B:36:0x0139, B:58:0x0262, B:63:0x0273, B:64:0x0270, B:65:0x026a), top: B:3:0x0012, outer: #7 }] */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r26) {
        /*
            Method dump skipped, instructions count: 696
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p009a.C0858m.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
