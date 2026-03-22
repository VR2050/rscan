package androidx.lifecycle;

import androidx.annotation.RequiresApi;
import androidx.exifinterface.media.ExifInterface;
import java.time.Duration;
import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.JvmName;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.p383b2.C3016l;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a9\u0010\u0007\u001a\b\u0012\u0004\u0012\u00028\u00000\u0006\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u00012\b\b\u0002\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u0004H\u0007¢\u0006\u0004\b\u0007\u0010\b\u001a#\u0010\t\u001a\b\u0012\u0004\u0012\u00028\u00000\u0001\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u0006¢\u0006\u0004\b\t\u0010\n\u001a7\u0010\u0007\u001a\b\u0012\u0004\u0012\u00028\u00000\u0006\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u00012\b\b\u0002\u0010\u0003\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u000bH\u0007¢\u0006\u0004\b\u0007\u0010\r¨\u0006\u000e"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/b2/b;", "Lkotlin/coroutines/CoroutineContext;", "context", "", "timeoutInMs", "Landroidx/lifecycle/LiveData;", "asLiveData", "(Lc/a/b2/b;Lkotlin/coroutines/CoroutineContext;J)Landroidx/lifecycle/LiveData;", "asFlow", "(Landroidx/lifecycle/LiveData;)Lc/a/b2/b;", "Ljava/time/Duration;", "timeout", "(Lc/a/b2/b;Lkotlin/coroutines/CoroutineContext;Ljava/time/Duration;)Landroidx/lifecycle/LiveData;", "lifecycle-livedata-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
@JvmName(name = "FlowLiveDataConversions")
/* loaded from: classes.dex */
public final class FlowLiveDataConversions {
    @NotNull
    public static final <T> InterfaceC3006b<T> asFlow(@NotNull LiveData<T> asFlow) {
        Intrinsics.checkParameterIsNotNull(asFlow, "$this$asFlow");
        return new C3016l(new FlowLiveDataConversions$asFlow$1(asFlow, null));
    }

    @JvmOverloads
    @NotNull
    public static final <T> LiveData<T> asLiveData(@NotNull InterfaceC3006b<? extends T> interfaceC3006b) {
        return asLiveData$default(interfaceC3006b, (CoroutineContext) null, 0L, 3, (Object) null);
    }

    @JvmOverloads
    @NotNull
    public static final <T> LiveData<T> asLiveData(@NotNull InterfaceC3006b<? extends T> interfaceC3006b, @NotNull CoroutineContext coroutineContext) {
        return asLiveData$default(interfaceC3006b, coroutineContext, 0L, 2, (Object) null);
    }

    @JvmOverloads
    @NotNull
    public static final <T> LiveData<T> asLiveData(@NotNull InterfaceC3006b<? extends T> asLiveData, @NotNull CoroutineContext context, long j2) {
        Intrinsics.checkParameterIsNotNull(asLiveData, "$this$asLiveData");
        Intrinsics.checkParameterIsNotNull(context, "context");
        return CoroutineLiveDataKt.liveData(context, j2, new FlowLiveDataConversions$asLiveData$1(asLiveData, null));
    }

    public static /* synthetic */ LiveData asLiveData$default(InterfaceC3006b interfaceC3006b, CoroutineContext coroutineContext, long j2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            coroutineContext = EmptyCoroutineContext.INSTANCE;
        }
        if ((i2 & 2) != 0) {
            j2 = 5000;
        }
        return asLiveData(interfaceC3006b, coroutineContext, j2);
    }

    @RequiresApi(26)
    @NotNull
    public static final <T> LiveData<T> asLiveData(@NotNull InterfaceC3006b<? extends T> asLiveData, @NotNull CoroutineContext context, @NotNull Duration timeout) {
        Intrinsics.checkParameterIsNotNull(asLiveData, "$this$asLiveData");
        Intrinsics.checkParameterIsNotNull(context, "context");
        Intrinsics.checkParameterIsNotNull(timeout, "timeout");
        return asLiveData(asLiveData, context, timeout.toMillis());
    }

    public static /* synthetic */ LiveData asLiveData$default(InterfaceC3006b interfaceC3006b, CoroutineContext coroutineContext, Duration duration, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            coroutineContext = EmptyCoroutineContext.INSTANCE;
        }
        return asLiveData(interfaceC3006b, coroutineContext, duration);
    }
}
