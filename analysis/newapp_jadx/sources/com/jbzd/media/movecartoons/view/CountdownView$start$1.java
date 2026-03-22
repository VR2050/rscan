package com.jbzd.media.movecartoons.view;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.view.CountdownView$start$1", m5320f = "CountdownView.kt", m5321i = {0}, m5322l = {81}, m5323m = "invokeSuspend", m5324n = {"i"}, m5325s = {"I$1"})
/* loaded from: classes2.dex */
public final class CountdownView$start$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public int I$0;
    public int I$1;
    public int label;
    public final /* synthetic */ CountdownView this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CountdownView$start$1(CountdownView countdownView, Continuation<? super CountdownView$start$1> continuation) {
        super(2, continuation);
        this.this$0 = countdownView;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new CountdownView$start$1(this.this$0, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((CountdownView$start$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x003a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x006c  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:11:0x0038 -> B:5:0x003b). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r7) {
        /*
            r6 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r6.label
            r2 = 1
            if (r1 == 0) goto L1c
            if (r1 != r2) goto L14
            int r1 = r6.I$1
            int r3 = r6.I$0
            kotlin.ResultKt.throwOnFailure(r7)
            r7 = r6
            goto L3b
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            kotlin.ResultKt.throwOnFailure(r7)
            com.jbzd.media.movecartoons.view.CountdownView r7 = r6.this$0
            long r3 = com.jbzd.media.movecartoons.view.CountdownView.access$getGap$p(r7)
            int r7 = (int) r3
            if (r7 < 0) goto L6e
            r1 = r7
            r7 = r6
        L2a:
            int r3 = r1 + (-1)
            r4 = 1000(0x3e8, double:4.94E-321)
            r7.I$0 = r3
            r7.I$1 = r1
            r7.label = r2
            java.lang.Object r4 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2422Q(r4, r7)
            if (r4 != r0) goto L3b
            return r0
        L3b:
            com.jbzd.media.movecartoons.view.CountdownView r4 = r7.this$0
            kotlin.jvm.functions.Function1 r4 = r4.getTimedBlock()
            java.lang.String r5 = java.lang.String.valueOf(r1)
            r4.invoke(r5)
            if (r1 != 0) goto L64
            com.jbzd.media.movecartoons.view.CountdownView r1 = r7.this$0
            kotlin.jvm.functions.Function1 r1 = r1.getExpiredBlock()
            r4 = 0
            java.lang.Boolean r4 = kotlin.coroutines.jvm.internal.Boxing.boxBoolean(r4)
            r1.invoke(r4)
            com.jbzd.media.movecartoons.view.CountdownView r1 = r7.this$0
            android.widget.TextView r1 = com.jbzd.media.movecartoons.view.CountdownView.access$getTv(r1)
            java.lang.String r4 = ""
            r1.setText(r4)
            goto L69
        L64:
            com.jbzd.media.movecartoons.view.CountdownView r4 = r7.this$0
            com.jbzd.media.movecartoons.view.CountdownView.access$setView(r4, r1)
        L69:
            if (r3 >= 0) goto L6c
            goto L6e
        L6c:
            r1 = r3
            goto L2a
        L6e:
            kotlin.Unit r7 = kotlin.Unit.INSTANCE
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.view.CountdownView$start$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
