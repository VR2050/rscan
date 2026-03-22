package androidx.lifecycle;

import androidx.exifinterface.media.ExifInterface;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u0010\u0005\u001a\u00020\u0002\"\u0004\b\u0000\u0010\u0000*\u00020\u0001H\u008a@¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/e0;", "Landroidx/lifecycle/EmittedSource;", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
@DebugMetadata(m5319c = "androidx.lifecycle.CoroutineLiveDataKt$addDisposableSource$2", m5320f = "CoroutineLiveData.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes.dex */
public final class CoroutineLiveDataKt$addDisposableSource$2 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super EmittedSource>, Object> {
    public final /* synthetic */ LiveData $source;
    public final /* synthetic */ MediatorLiveData $this_addDisposableSource;
    public int label;

    /* renamed from: p$ */
    private InterfaceC3055e0 f175p$;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CoroutineLiveDataKt$addDisposableSource$2(MediatorLiveData mediatorLiveData, LiveData liveData, Continuation continuation) {
        super(2, continuation);
        this.$this_addDisposableSource = mediatorLiveData;
        this.$source = liveData;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkParameterIsNotNull(completion, "completion");
        CoroutineLiveDataKt$addDisposableSource$2 coroutineLiveDataKt$addDisposableSource$2 = new CoroutineLiveDataKt$addDisposableSource$2(this.$this_addDisposableSource, this.$source, completion);
        coroutineLiveDataKt$addDisposableSource$2.f175p$ = (InterfaceC3055e0) obj;
        return coroutineLiveDataKt$addDisposableSource$2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super EmittedSource> continuation) {
        return ((CoroutineLiveDataKt$addDisposableSource$2) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        ResultKt.throwOnFailure(obj);
        this.$this_addDisposableSource.addSource(this.$source, new Observer<S>() { // from class: androidx.lifecycle.CoroutineLiveDataKt$addDisposableSource$2.1
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                CoroutineLiveDataKt$addDisposableSource$2.this.$this_addDisposableSource.setValue(t);
            }
        });
        return new EmittedSource(this.$source, this.$this_addDisposableSource);
    }
}
