package com.jbzd.media.movecartoons.p396ui.accountvoucher;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p383b2.InterfaceC3007c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0004\u001a\u00020\u0003*\u0010\u0012\f\u0012\n \u0002*\u0004\u0018\u00010\u00010\u00010\u0000H\u008a@¢\u0006\u0004\b\u0004\u0010\u0005"}, m5311d2 = {"Lc/a/b2/c;", "", "kotlin.jvm.PlatformType", "", "<anonymous>", "(Lc/a/b2/c;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$parsePhoto$1", m5320f = "FindActivity.kt", m5321i = {}, m5322l = {63}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class FindActivity$parsePhoto$1 extends SuspendLambda implements Function2<InterfaceC3007c<? super String>, Continuation<? super Unit>, Object> {
    public final /* synthetic */ String $path;
    private /* synthetic */ Object L$0;
    public int label;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FindActivity$parsePhoto$1(String str, Continuation<? super FindActivity$parsePhoto$1> continuation) {
        super(2, continuation);
        this.$path = str;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        FindActivity$parsePhoto$1 findActivity$parsePhoto$1 = new FindActivity$parsePhoto$1(this.$path, continuation);
        findActivity$parsePhoto$1.L$0 = obj;
        return findActivity$parsePhoto$1;
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3007c<? super String> interfaceC3007c, @Nullable Continuation<? super Unit> continuation) {
        return ((FindActivity$parsePhoto$1) create(interfaceC3007c, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(21:10|11|12|(2:14|(17:16|17|(1:19)|20|22|23|(1:25)|26|27|(5:49|50|(1:52)|53|54)(1:29)|(4:42|43|(1:45)|46)|31|32|33|(1:35)|36|(1:38)))|(2:60|(17:62|17|(0)|20|22|23|(0)|26|27|(0)(0)|(0)|31|32|33|(0)|36|(0)))|63|(0)|20|22|23|(0)|26|27|(0)(0)|(0)|31|32|33|(0)|36|(0)) */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x010e, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0112, code lost:
    
        r0.printStackTrace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00cf, code lost:
    
        r0 = null;
        r5 = true;
     */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00c6 A[Catch: Exception -> 0x00cf, TryCatch #2 {Exception -> 0x00cf, blocks: (B:23:0x00b8, B:25:0x00c6, B:26:0x00c9), top: B:22:0x00b8 }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0121 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00f4 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00d3 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 293
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.accountvoucher.FindActivity$parsePhoto$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
