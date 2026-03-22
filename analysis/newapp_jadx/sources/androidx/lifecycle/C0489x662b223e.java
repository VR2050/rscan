package androidx.lifecycle;

import androidx.exifinterface.media.ExifInterface;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p383b2.InterfaceC3007c;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0013\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u001b\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0002\u001a\u00028\u0000H\u0096@ø\u0001\u0000¢\u0006\u0004\b\u0004\u0010\u0005\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0006"}, m5311d2 = {"kotlinx/coroutines/flow/FlowKt__CollectKt$collect$3", "Lc/a/b2/c;", "value", "", "emit", "(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "kotlinx-coroutines-core"}, m5312k = 1, m5313mv = {1, 4, 0})
/* renamed from: androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1 */
/* loaded from: classes.dex */
public final class C0489x662b223e<T> implements InterfaceC3007c<T> {
    public final /* synthetic */ LiveDataScope $this_liveData$inlined;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\u0010\u0006\u001a\u0004\u0018\u00010\u0005\"\u0004\b\u0000\u0010\u00002\u0006\u0010\u0001\u001a\u00028\u00002\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H\u0096@"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "value", "LLkotlin/coroutines/Continuation;;", "L;", "continuation", "", "emit"}, m5312k = 3, m5313mv = {1, 4, 0})
    @DebugMetadata(m5319c = "androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1", m5320f = "FlowLiveData.kt", m5321i = {0, 0, 0, 0}, m5322l = {136}, m5323m = "emit", m5324n = {"this", "value", "continuation", "it"}, m5325s = {"L$0", "L$1", "L$2", "L$3"})
    /* renamed from: androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1$1, reason: invalid class name */
    public final class AnonymousClass1 extends ContinuationImpl {
        public Object L$0;
        public Object L$1;
        public Object L$2;
        public Object L$3;
        public int label;
        public /* synthetic */ Object result;

        public AnonymousClass1(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.result = obj;
            this.label |= Integer.MIN_VALUE;
            return C0489x662b223e.this.emit(null, this);
        }
    }

    public C0489x662b223e(LiveDataScope liveDataScope) {
        this.$this_liveData$inlined = liveDataScope;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0039  */
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
            boolean r0 = r6 instanceof androidx.lifecycle.C0489x662b223e.AnonymousClass1
            if (r0 == 0) goto L13
            r0 = r6
            androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1$1 r0 = (androidx.lifecycle.C0489x662b223e.AnonymousClass1) r0
            int r1 = r0.label
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.label = r1
            goto L18
        L13:
            androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1$1 r0 = new androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1$1
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.result
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.label
            r3 = 1
            if (r2 == 0) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r5 = r0.L$2
            kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
            java.lang.Object r5 = r0.L$0
            androidx.lifecycle.FlowLiveDataConversions$asLiveData$1$invokeSuspend$$inlined$collect$1 r5 = (androidx.lifecycle.C0489x662b223e) r5
            kotlin.ResultKt.throwOnFailure(r6)
            goto L4f
        L31:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L39:
            kotlin.ResultKt.throwOnFailure(r6)
            androidx.lifecycle.LiveDataScope r6 = r4.$this_liveData$inlined
            r0.L$0 = r4
            r0.L$1 = r5
            r0.L$2 = r0
            r0.L$3 = r5
            r0.label = r3
            java.lang.Object r5 = r6.emit(r5, r0)
            if (r5 != r1) goto L4f
            return r1
        L4f:
            kotlin.Unit r5 = kotlin.Unit.INSTANCE
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.C0489x662b223e.emit(java.lang.Object, kotlin.coroutines.Continuation):java.lang.Object");
    }
}
