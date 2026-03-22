package android.view;

import androidx.annotation.IdRes;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0006\u001a\u001e\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\b\b\u0001\u0010\u0002\u001a\u00020\u0001H\u0086\n¢\u0006\u0004\b\u0004\u0010\u0005\u001a\u001e\u0010\u0007\u001a\u00020\u0006*\u00020\u00002\b\b\u0001\u0010\u0002\u001a\u00020\u0001H\u0086\u0002¢\u0006\u0004\b\u0007\u0010\b\u001a\u001c\u0010\u000b\u001a\u00020\n*\u00020\u00002\u0006\u0010\t\u001a\u00020\u0003H\u0086\n¢\u0006\u0004\b\u000b\u0010\f\u001a\u001c\u0010\u000b\u001a\u00020\n*\u00020\u00002\u0006\u0010\r\u001a\u00020\u0000H\u0086\n¢\u0006\u0004\b\u000b\u0010\u000e\u001a\u001c\u0010\u000f\u001a\u00020\n*\u00020\u00002\u0006\u0010\t\u001a\u00020\u0003H\u0086\n¢\u0006\u0004\b\u000f\u0010\f¨\u0006\u0010"}, m5311d2 = {"Landroidx/navigation/NavGraph;", "", "id", "Landroidx/navigation/NavDestination;", "get", "(Landroidx/navigation/NavGraph;I)Landroidx/navigation/NavDestination;", "", "contains", "(Landroidx/navigation/NavGraph;I)Z", "node", "", "plusAssign", "(Landroidx/navigation/NavGraph;Landroidx/navigation/NavDestination;)V", "other", "(Landroidx/navigation/NavGraph;Landroidx/navigation/NavGraph;)V", "minusAssign", "navigation-common-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavGraphKt {
    public static final boolean contains(@NotNull NavGraph contains, @IdRes int i2) {
        Intrinsics.checkParameterIsNotNull(contains, "$this$contains");
        return contains.findNode(i2) != null;
    }

    @NotNull
    public static final NavDestination get(@NotNull NavGraph get, @IdRes int i2) {
        Intrinsics.checkParameterIsNotNull(get, "$this$get");
        NavDestination findNode = get.findNode(i2);
        if (findNode != null) {
            return findNode;
        }
        throw new IllegalArgumentException("No destination for " + i2 + " was found in " + get);
    }

    public static final void minusAssign(@NotNull NavGraph minusAssign, @NotNull NavDestination node) {
        Intrinsics.checkParameterIsNotNull(minusAssign, "$this$minusAssign");
        Intrinsics.checkParameterIsNotNull(node, "node");
        minusAssign.remove(node);
    }

    public static final void plusAssign(@NotNull NavGraph plusAssign, @NotNull NavDestination node) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        Intrinsics.checkParameterIsNotNull(node, "node");
        plusAssign.addDestination(node);
    }

    public static final void plusAssign(@NotNull NavGraph plusAssign, @NotNull NavGraph other) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        Intrinsics.checkParameterIsNotNull(other, "other");
        plusAssign.addAll(other);
    }
}
