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
import p379c.p380a.p383b2.InterfaceC3007c;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0005\u001a\u00020\u0002\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u0001H\u008a@¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/b2/c;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
@DebugMetadata(m5319c = "androidx.lifecycle.FlowLiveDataConversions$asFlow$1", m5320f = "FlowLiveData.kt", m5321i = {0, 0, 0, 1, 1, 1, 2, 2, 2, 2}, m5322l = {91, 95, 96}, m5323m = "invokeSuspend", m5324n = {"$this$flow", "channel", "observer", "$this$flow", "channel", "observer", "$this$flow", "channel", "observer", "value"}, m5325s = {"L$0", "L$1", "L$2", "L$0", "L$1", "L$2", "L$0", "L$1", "L$2", "L$3"})
/* loaded from: classes.dex */
public final class FlowLiveDataConversions$asFlow$1<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {
    public final /* synthetic */ LiveData $this_asFlow;
    public Object L$0;
    public Object L$1;
    public Object L$2;
    public Object L$3;
    public Object L$4;
    public int label;

    /* renamed from: p$ */
    private InterfaceC3007c f178p$;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0005\u001a\u00020\u0002\"\u0004\b\u0000\u0010\u0000*\u00020\u0001H\u008a@¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/e0;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
    @DebugMetadata(m5319c = "androidx.lifecycle.FlowLiveDataConversions$asFlow$1$1", m5320f = "FlowLiveData.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: androidx.lifecycle.FlowLiveDataConversions$asFlow$1$1 */
    public static final class C04901 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ Observer $observer;
        public int label;

        /* renamed from: p$ */
        private InterfaceC3055e0 f179p$;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C04901(Observer observer, Continuation continuation) {
            super(2, continuation);
            this.$observer = observer;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
            Intrinsics.checkParameterIsNotNull(completion, "completion");
            C04901 c04901 = new C04901(this.$observer, completion);
            c04901.f179p$ = (InterfaceC3055e0) obj;
            return c04901;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return ((C04901) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            FlowLiveDataConversions$asFlow$1.this.$this_asFlow.observeForever(this.$observer);
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0005\u001a\u00020\u0002\"\u0004\b\u0000\u0010\u0000*\u00020\u0001H\u008a@¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/e0;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
    @DebugMetadata(m5319c = "androidx.lifecycle.FlowLiveDataConversions$asFlow$1$2", m5320f = "FlowLiveData.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: androidx.lifecycle.FlowLiveDataConversions$asFlow$1$2 */
    public static final class C04912 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ Observer $observer;
        public int label;

        /* renamed from: p$ */
        private InterfaceC3055e0 f180p$;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C04912(Observer observer, Continuation continuation) {
            super(2, continuation);
            this.$observer = observer;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
            Intrinsics.checkParameterIsNotNull(completion, "completion");
            C04912 c04912 = new C04912(this.$observer, completion);
            c04912.f180p$ = (InterfaceC3055e0) obj;
            return c04912;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return ((C04912) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            FlowLiveDataConversions$asFlow$1.this.$this_asFlow.removeObserver(this.$observer);
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FlowLiveDataConversions$asFlow$1(LiveData liveData, Continuation continuation) {
        super(2, continuation);
        this.$this_asFlow = liveData;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkParameterIsNotNull(completion, "completion");
        FlowLiveDataConversions$asFlow$1 flowLiveDataConversions$asFlow$1 = new FlowLiveDataConversions$asFlow$1(this.$this_asFlow, completion);
        flowLiveDataConversions$asFlow$1.f178p$ = (InterfaceC3007c) obj;
        return flowLiveDataConversions$asFlow$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Continuation<? super Unit> continuation) {
        return ((FlowLiveDataConversions$asFlow$1) create(obj, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:11:0x00a6 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:13:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x00b6 A[Catch: all -> 0x00e5, TRY_LEAVE, TryCatch #0 {all -> 0x00e5, blocks: (B:15:0x00ae, B:17:0x00b6), top: B:14:0x00ae }] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x00cd  */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v17 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [androidx.lifecycle.Observer] */
    /* JADX WARN: Type inference failed for: r6v5, types: [androidx.lifecycle.Observer, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v2, types: [c.a.b2.c, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v5 */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(@org.jetbrains.annotations.NotNull java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.FlowLiveDataConversions$asFlow$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
