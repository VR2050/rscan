package com.jbzd.media.movecartoons.p396ui.mine;

import androidx.lifecycle.MutableLiveData;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.mine.MineViewModel$startTimeCountDown$1", m5320f = "MineViewModel.kt", m5321i = {0}, m5322l = {135, 136}, m5323m = "invokeSuspend", m5324n = {"i"}, m5325s = {"I$1"})
/* loaded from: classes2.dex */
public final class MineViewModel$startTimeCountDown$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public int I$0;
    public int I$1;
    public int label;
    public final /* synthetic */ MineViewModel this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.mine.MineViewModel$startTimeCountDown$1$1", m5320f = "MineViewModel.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.mine.MineViewModel$startTimeCountDown$1$1 */
    public static final class C38081 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: $i */
        public final /* synthetic */ int f10115$i;
        public int label;
        public final /* synthetic */ MineViewModel this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C38081(MineViewModel mineViewModel, int i2, Continuation<? super C38081> continuation) {
            super(2, continuation);
            this.this$0 = mineViewModel;
            this.f10115$i = i2;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38081(this.this$0, this.f10115$i, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38081) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            MutableLiveData<String> sendSmsText = this.this$0.getSendSmsText();
            int i2 = this.f10115$i;
            sendSmsText.setValue(i2 == 1 ? this.this$0.getSendSmsButtonText() : String.valueOf(i2 - 1));
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MineViewModel$startTimeCountDown$1(MineViewModel mineViewModel, Continuation<? super MineViewModel$startTimeCountDown$1> continuation) {
        super(2, continuation);
        this.this$0 = mineViewModel;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new MineViewModel$startTimeCountDown$1(this.this$0, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((MineViewModel$startTimeCountDown$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0055 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x003e A[RETURN] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:14:0x0056 -> B:6:0x0057). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r10) {
        /*
            r9 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r9.label
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L26
            if (r1 == r3) goto L1d
            if (r1 != r2) goto L15
            int r1 = r9.I$0
            kotlin.ResultKt.throwOnFailure(r10)
            r10 = r9
            goto L57
        L15:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1d:
            int r1 = r9.I$1
            int r4 = r9.I$0
            kotlin.ResultKt.throwOnFailure(r10)
            r10 = r9
            goto L3f
        L26:
            kotlin.ResultKt.throwOnFailure(r10)
            r10 = 60
            r10 = r9
            r1 = 60
        L2e:
            int r4 = r1 + (-1)
            r5 = 1000(0x3e8, double:4.94E-321)
            r10.I$0 = r4
            r10.I$1 = r1
            r10.label = r3
            java.lang.Object r5 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2422Q(r5, r10)
            if (r5 != r0) goto L3f
            return r0
        L3f:
            c.a.m0 r5 = p379c.p380a.C3079m0.f8432c
            c.a.l1 r5 = p379c.p380a.p381a.C2964m.f8127b
            com.jbzd.media.movecartoons.ui.mine.MineViewModel$startTimeCountDown$1$1 r6 = new com.jbzd.media.movecartoons.ui.mine.MineViewModel$startTimeCountDown$1$1
            com.jbzd.media.movecartoons.ui.mine.MineViewModel r7 = r10.this$0
            r8 = 0
            r6.<init>(r7, r1, r8)
            r10.I$0 = r4
            r10.label = r2
            java.lang.Object r1 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2471e2(r5, r6, r10)
            if (r1 != r0) goto L56
            return r0
        L56:
            r1 = r4
        L57:
            if (r3 <= r1) goto L2e
            kotlin.Unit r10 = kotlin.Unit.INSTANCE
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.mine.MineViewModel$startTimeCountDown$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
