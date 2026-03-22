package p005b.p006a.p007a.p008a.p017r;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.Api", m5320f = "Api.kt", m5321i = {}, m5322l = {240}, m5323m = "post", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.r.c */
/* loaded from: classes2.dex */
public final class C0919c extends ContinuationImpl {

    /* renamed from: c */
    public /* synthetic */ Object f430c;

    /* renamed from: e */
    public final /* synthetic */ C0917a f431e;

    /* renamed from: f */
    public int f432f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0919c(C0917a c0917a, Continuation<? super C0919c> continuation) {
        super(continuation);
        this.f431e = c0917a;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        this.f430c = obj;
        this.f432f |= Integer.MIN_VALUE;
        return C0917a.m220b(this.f431e, null, null, this);
    }
}
