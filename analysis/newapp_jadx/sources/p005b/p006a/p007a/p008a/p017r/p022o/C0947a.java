package p005b.p006a.p007a.p008a.p017r.p022o;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.upload.UploadPicController", m5320f = "UploadPicController.kt", m5321i = {}, m5322l = {113}, m5323m = "doUpload", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.r.o.a */
/* loaded from: classes2.dex */
public final class C0947a extends ContinuationImpl {

    /* renamed from: c */
    public /* synthetic */ Object f483c;

    /* renamed from: e */
    public final /* synthetic */ C0949c f484e;

    /* renamed from: f */
    public int f485f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0947a(C0949c c0949c, Continuation<? super C0947a> continuation) {
        super(continuation);
        this.f484e = c0949c;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        this.f483c = obj;
        this.f485f |= Integer.MIN_VALUE;
        return C0949c.m290a(this.f484e, null, this);
    }
}
