package androidx.work;

import androidx.annotation.RequiresApi;
import androidx.exifinterface.media.ExifInterface;
import androidx.work.PeriodicWorkRequest;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u001a,\u0010\u0007\u001a\u00020\u0006\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0086\b¢\u0006\u0004\b\u0007\u0010\b\u001a$\u0010\u0007\u001a\u00020\u0006\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u00002\u0006\u0010\u0003\u001a\u00020\tH\u0087\b¢\u0006\u0004\b\u0007\u0010\n\u001a<\u0010\u0007\u001a\u00020\u0006\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u0004H\u0086\b¢\u0006\u0004\b\u0007\u0010\r\u001a,\u0010\u0007\u001a\u00020\u0006\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u00002\u0006\u0010\u0003\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00020\tH\u0087\b¢\u0006\u0004\b\u0007\u0010\u000e¨\u0006\u000f"}, m5311d2 = {"Landroidx/work/ListenableWorker;", ExifInterface.LONGITUDE_WEST, "", "repeatInterval", "Ljava/util/concurrent/TimeUnit;", "repeatIntervalTimeUnit", "Landroidx/work/PeriodicWorkRequest$Builder;", "PeriodicWorkRequestBuilder", "(JLjava/util/concurrent/TimeUnit;)Landroidx/work/PeriodicWorkRequest$Builder;", "Ljava/time/Duration;", "(Ljava/time/Duration;)Landroidx/work/PeriodicWorkRequest$Builder;", "flexTimeInterval", "flexTimeIntervalUnit", "(JLjava/util/concurrent/TimeUnit;JLjava/util/concurrent/TimeUnit;)Landroidx/work/PeriodicWorkRequest$Builder;", "(Ljava/time/Duration;Ljava/time/Duration;)Landroidx/work/PeriodicWorkRequest$Builder;", "work-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class PeriodicWorkRequestKt {
    @NotNull
    public static final /* synthetic */ <W extends ListenableWorker> PeriodicWorkRequest.Builder PeriodicWorkRequestBuilder(long j2, @NotNull TimeUnit repeatIntervalTimeUnit) {
        Intrinsics.checkParameterIsNotNull(repeatIntervalTimeUnit, "repeatIntervalTimeUnit");
        Intrinsics.reifiedOperationMarker(4, ExifInterface.LONGITUDE_WEST);
        return new PeriodicWorkRequest.Builder((Class<? extends ListenableWorker>) ListenableWorker.class, j2, repeatIntervalTimeUnit);
    }

    @RequiresApi(26)
    @NotNull
    public static final /* synthetic */ <W extends ListenableWorker> PeriodicWorkRequest.Builder PeriodicWorkRequestBuilder(@NotNull Duration repeatInterval) {
        Intrinsics.checkParameterIsNotNull(repeatInterval, "repeatInterval");
        Intrinsics.reifiedOperationMarker(4, ExifInterface.LONGITUDE_WEST);
        return new PeriodicWorkRequest.Builder(ListenableWorker.class, repeatInterval);
    }

    @NotNull
    public static final /* synthetic */ <W extends ListenableWorker> PeriodicWorkRequest.Builder PeriodicWorkRequestBuilder(long j2, @NotNull TimeUnit repeatIntervalTimeUnit, long j3, @NotNull TimeUnit flexTimeIntervalUnit) {
        Intrinsics.checkParameterIsNotNull(repeatIntervalTimeUnit, "repeatIntervalTimeUnit");
        Intrinsics.checkParameterIsNotNull(flexTimeIntervalUnit, "flexTimeIntervalUnit");
        Intrinsics.reifiedOperationMarker(4, ExifInterface.LONGITUDE_WEST);
        return new PeriodicWorkRequest.Builder(ListenableWorker.class, j2, repeatIntervalTimeUnit, j3, flexTimeIntervalUnit);
    }

    @RequiresApi(26)
    @NotNull
    public static final /* synthetic */ <W extends ListenableWorker> PeriodicWorkRequest.Builder PeriodicWorkRequestBuilder(@NotNull Duration repeatInterval, @NotNull Duration flexTimeInterval) {
        Intrinsics.checkParameterIsNotNull(repeatInterval, "repeatInterval");
        Intrinsics.checkParameterIsNotNull(flexTimeInterval, "flexTimeInterval");
        Intrinsics.reifiedOperationMarker(4, ExifInterface.LONGITUDE_WEST);
        return new PeriodicWorkRequest.Builder((Class<? extends ListenableWorker>) ListenableWorker.class, repeatInterval, flexTimeInterval);
    }
}
