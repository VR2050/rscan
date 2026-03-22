package androidx.databinding;

import androidx.databinding.ViewDataBindingKtx;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0004\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 2})
@DebugMetadata(m5319c = "androidx.databinding.ViewDataBindingKtx$StateFlowListener$startCollection$1", m5320f = "ViewDataBindingKtx.kt", m5321i = {}, m5322l = {116}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes.dex */
public final class ViewDataBindingKtx$StateFlowListener$startCollection$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ InterfaceC3006b $flow;
    public int label;
    public final /* synthetic */ ViewDataBindingKtx.StateFlowListener this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ViewDataBindingKtx$StateFlowListener$startCollection$1(ViewDataBindingKtx.StateFlowListener stateFlowListener, InterfaceC3006b interfaceC3006b, Continuation continuation) {
        super(2, continuation);
        this.this$0 = stateFlowListener;
        this.$flow = interfaceC3006b;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkNotNullParameter(completion, "completion");
        return new ViewDataBindingKtx$StateFlowListener$startCollection$1(this.this$0, this.$flow, completion);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return ((ViewDataBindingKtx$StateFlowListener$startCollection$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3006b interfaceC3006b = this.$flow;
            InterfaceC3007c<Object> interfaceC3007c = new InterfaceC3007c<Object>() { // from class: androidx.databinding.ViewDataBindingKtx$StateFlowListener$startCollection$1$invokeSuspend$$inlined$collect$1
                @Override // p379c.p380a.p383b2.InterfaceC3007c
                @Nullable
                public Object emit(Object obj2, @NotNull Continuation continuation) {
                    WeakListener weakListener;
                    Unit unit;
                    WeakListener weakListener2;
                    WeakListener weakListener3;
                    weakListener = ViewDataBindingKtx$StateFlowListener$startCollection$1.this.this$0.listener;
                    ViewDataBinding binder = weakListener.getBinder();
                    if (binder != null) {
                        weakListener2 = ViewDataBindingKtx$StateFlowListener$startCollection$1.this.this$0.listener;
                        int i3 = weakListener2.mLocalFieldId;
                        weakListener3 = ViewDataBindingKtx$StateFlowListener$startCollection$1.this.this$0.listener;
                        binder.handleFieldChange(i3, weakListener3.getTarget(), 0);
                        unit = Unit.INSTANCE;
                    } else {
                        unit = null;
                    }
                    return unit == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? unit : Unit.INSTANCE;
                }
            };
            this.label = 1;
            if (interfaceC3006b.mo289a(interfaceC3007c, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
        }
        return Unit.INSTANCE;
    }
}
