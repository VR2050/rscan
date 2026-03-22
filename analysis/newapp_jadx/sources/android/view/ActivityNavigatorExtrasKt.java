package android.view;

import android.view.ActivityNavigator;
import androidx.core.app.ActivityOptionsCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a#\u0010\u0005\u001a\u00020\u00042\n\b\u0002\u0010\u0001\u001a\u0004\u0018\u00010\u00002\b\b\u0002\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\u0007"}, m5311d2 = {"Landroidx/core/app/ActivityOptionsCompat;", "activityOptions", "", "flags", "Landroidx/navigation/ActivityNavigator$Extras;", "ActivityNavigatorExtras", "(Landroidx/core/app/ActivityOptionsCompat;I)Landroidx/navigation/ActivityNavigator$Extras;", "navigation-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class ActivityNavigatorExtrasKt {
    @NotNull
    public static final ActivityNavigator.Extras ActivityNavigatorExtras(@Nullable ActivityOptionsCompat activityOptionsCompat, int i2) {
        ActivityNavigator.Extras.Builder builder = new ActivityNavigator.Extras.Builder();
        if (activityOptionsCompat != null) {
            builder.setActivityOptions(activityOptionsCompat);
        }
        builder.addFlags(i2);
        ActivityNavigator.Extras build = builder.build();
        Intrinsics.checkExpressionValueIsNotNull(build, "ActivityNavigator.Extras…(flags)\n        }.build()");
        return build;
    }

    public static /* synthetic */ ActivityNavigator.Extras ActivityNavigatorExtras$default(ActivityOptionsCompat activityOptionsCompat, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            activityOptionsCompat = null;
        }
        if ((i3 & 2) != 0) {
            i2 = 0;
        }
        return ActivityNavigatorExtras(activityOptionsCompat, i2);
    }
}
