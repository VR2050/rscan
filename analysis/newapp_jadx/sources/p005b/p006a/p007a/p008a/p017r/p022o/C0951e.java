package p005b.p006a.p007a.p008a.p017r.p022o;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadVideoController", m5320f = "UploadVideoController.kt", m5321i = {}, m5322l = {133}, m5323m = "uploadSlice", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.r.o.e */
/* loaded from: classes2.dex */
public final class C0951e extends ContinuationImpl {

    /* renamed from: c */
    public Object f555c;

    /* renamed from: e */
    public /* synthetic */ Object f556e;

    /* renamed from: f */
    public final /* synthetic */ C0950d f557f;

    /* renamed from: g */
    public int f558g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0951e(C0950d c0950d, Continuation<? super C0951e> continuation) {
        super(continuation);
        this.f557f = c0950d;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        this.f556e = obj;
        this.f558g |= Integer.MIN_VALUE;
        return C0950d.m294b(this.f557f, null, this);
    }
}
