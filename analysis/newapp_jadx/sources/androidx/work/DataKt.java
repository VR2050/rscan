package androidx.work;

import androidx.exifinterface.media.ExifInterface;
import androidx.work.Data;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\u001a@\u0010\u0006\u001a\u00020\u00052.\u0010\u0004\u001a\u0018\u0012\u0014\b\u0001\u0012\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u00010\u0000\"\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u0001H\u0086\b¢\u0006\u0004\b\u0006\u0010\u0007\u001a(\u0010\u000b\u001a\u00020\n\"\n\b\u0000\u0010\b\u0018\u0001*\u00020\u0003*\u00020\u00052\u0006\u0010\t\u001a\u00020\u0002H\u0086\b¢\u0006\u0004\b\u000b\u0010\f¨\u0006\r"}, m5311d2 = {"", "Lkotlin/Pair;", "", "", "pairs", "Landroidx/work/Data;", "workDataOf", "([Lkotlin/Pair;)Landroidx/work/Data;", ExifInterface.GPS_DIRECTION_TRUE, "key", "", "hasKeyWithValueOfType", "(Landroidx/work/Data;Ljava/lang/String;)Z", "work-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class DataKt {
    public static final /* synthetic */ <T> boolean hasKeyWithValueOfType(@NotNull Data hasKeyWithValueOfType, @NotNull String key) {
        Intrinsics.checkParameterIsNotNull(hasKeyWithValueOfType, "$this$hasKeyWithValueOfType");
        Intrinsics.checkParameterIsNotNull(key, "key");
        Intrinsics.reifiedOperationMarker(4, ExifInterface.GPS_DIRECTION_TRUE);
        return hasKeyWithValueOfType.hasKeyWithValueOfType(key, Object.class);
    }

    @NotNull
    public static final Data workDataOf(@NotNull Pair<String, ? extends Object>... pairs) {
        Intrinsics.checkParameterIsNotNull(pairs, "pairs");
        Data.Builder builder = new Data.Builder();
        for (Pair<String, ? extends Object> pair : pairs) {
            builder.put(pair.getFirst(), pair.getSecond());
        }
        Data build = builder.build();
        Intrinsics.checkExpressionValueIsNotNull(build, "dataBuilder.build()");
        return build;
    }
}
