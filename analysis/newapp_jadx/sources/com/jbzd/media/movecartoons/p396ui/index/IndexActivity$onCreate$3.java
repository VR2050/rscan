package com.jbzd.media.movecartoons.p396ui.index;

import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Ref;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.index.IndexActivity$onCreate$3", m5320f = "IndexActivity.kt", m5321i = {1, 2}, m5322l = {285, 289, 296, 303}, m5323m = "invokeSuspend", m5324n = {"destination$iv$iv", "destination$iv$iv"}, m5325s = {"L$1", "L$1"})
/* loaded from: classes2.dex */
public final class IndexActivity$onCreate$3 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ Ref.ObjectRef<List<AppItemNew>> $apps;
    public final /* synthetic */ Ref.ObjectRef<List<AdBean>> $layers;
    public final /* synthetic */ Ref.ObjectRef<List<List<AdBean>>> $layers2;
    public final /* synthetic */ Ref.ObjectRef<String> $notice;
    public Object L$0;
    public Object L$1;
    public Object L$2;
    public Object L$3;
    public int label;
    public final /* synthetic */ IndexActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public IndexActivity$onCreate$3(Ref.ObjectRef<List<AppItemNew>> objectRef, Ref.ObjectRef<List<List<AdBean>>> objectRef2, Ref.ObjectRef<List<AdBean>> objectRef3, Ref.ObjectRef<String> objectRef4, IndexActivity indexActivity, Continuation<? super IndexActivity$onCreate$3> continuation) {
        super(2, continuation);
        this.$apps = objectRef;
        this.$layers2 = objectRef2;
        this.$layers = objectRef3;
        this.$notice = objectRef4;
        this.this$0 = indexActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new IndexActivity$onCreate$3(this.$apps, this.$layers2, this.$layers, this.$notice, this.this$0, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((IndexActivity$onCreate$3) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00d6  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:20:0x011b -> B:14:0x011c). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:34:0x00ce -> B:28:0x00cf). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r11) {
        /*
            Method dump skipped, instructions count: 339
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.index.IndexActivity$onCreate$3.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
