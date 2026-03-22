package android.view;

import android.view.NavArgument;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@NavDestinationDsl
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\t\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u001e\u0010\u001fJ\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004R\u0016\u0010\u0006\u001a\u00020\u00058\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0006\u0010\u0007R.\u0010\t\u001a\u0004\u0018\u00010\u00012\b\u0010\b\u001a\u0004\u0018\u00010\u00018\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR,\u0010\u0014\u001a\u0006\u0012\u0002\b\u00030\u000f2\n\u0010\b\u001a\u0006\u0012\u0002\b\u00030\u000f8F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b\u0010\u0010\u0011\"\u0004\b\u0012\u0010\u0013R\u001c\u0010\u0015\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R*\u0010\u0018\u001a\u00020\u00172\u0006\u0010\b\u001a\u00020\u00178\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001b\"\u0004\b\u001c\u0010\u001d¨\u0006 "}, m5311d2 = {"Landroidx/navigation/NavArgumentBuilder;", "", "Landroidx/navigation/NavArgument;", "build", "()Landroidx/navigation/NavArgument;", "Landroidx/navigation/NavArgument$Builder;", "builder", "Landroidx/navigation/NavArgument$Builder;", "value", "defaultValue", "Ljava/lang/Object;", "getDefaultValue", "()Ljava/lang/Object;", "setDefaultValue", "(Ljava/lang/Object;)V", "Landroidx/navigation/NavType;", "getType", "()Landroidx/navigation/NavType;", "setType", "(Landroidx/navigation/NavType;)V", "type", "_type", "Landroidx/navigation/NavType;", "", "nullable", "Z", "getNullable", "()Z", "setNullable", "(Z)V", "<init>", "()V", "navigation-common-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavArgumentBuilder {
    private NavType<?> _type;
    private final NavArgument.Builder builder = new NavArgument.Builder();

    @Nullable
    private Object defaultValue;
    private boolean nullable;

    @NotNull
    public final NavArgument build() {
        NavArgument build = this.builder.build();
        Intrinsics.checkExpressionValueIsNotNull(build, "builder.build()");
        return build;
    }

    @Nullable
    public final Object getDefaultValue() {
        return this.defaultValue;
    }

    public final boolean getNullable() {
        return this.nullable;
    }

    @NotNull
    public final NavType<?> getType() {
        NavType<?> navType = this._type;
        if (navType != null) {
            return navType;
        }
        throw new IllegalStateException("NavType has not been set on this builder.");
    }

    public final void setDefaultValue(@Nullable Object obj) {
        this.defaultValue = obj;
        this.builder.setDefaultValue(obj);
    }

    public final void setNullable(boolean z) {
        this.nullable = z;
        this.builder.setIsNullable(z);
    }

    public final void setType(@NotNull NavType<?> value) {
        Intrinsics.checkParameterIsNotNull(value, "value");
        this._type = value;
        this.builder.setType(value);
    }
}
