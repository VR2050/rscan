package androidx.fragment.app;

import android.os.Bundle;
import androidx.annotation.IdRes;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\u001aB\u0010\t\u001a\u00020\u0002\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\b\b\u0001\u0010\u0004\u001a\u00020\u00032\n\b\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0086\b¢\u0006\u0004\b\t\u0010\n\u001a4\u0010\t\u001a\u00020\u0002\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0086\b¢\u0006\u0004\b\t\u0010\u000b\u001aB\u0010\f\u001a\u00020\u0002\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\b\b\u0001\u0010\u0004\u001a\u00020\u00032\n\b\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0086\b¢\u0006\u0004\b\f\u0010\n¨\u0006\r"}, m5311d2 = {"Landroidx/fragment/app/Fragment;", "F", "Landroidx/fragment/app/FragmentTransaction;", "", "containerViewId", "", "tag", "Landroid/os/Bundle;", "args", "add", "(Landroidx/fragment/app/FragmentTransaction;ILjava/lang/String;Landroid/os/Bundle;)Landroidx/fragment/app/FragmentTransaction;", "(Landroidx/fragment/app/FragmentTransaction;Ljava/lang/String;Landroid/os/Bundle;)Landroidx/fragment/app/FragmentTransaction;", "replace", "fragment-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class FragmentTransactionKt {
    @NotNull
    public static final /* synthetic */ <F extends Fragment> FragmentTransaction add(@NotNull FragmentTransaction add, @IdRes int i2, @Nullable String str, @Nullable Bundle bundle) {
        Intrinsics.checkParameterIsNotNull(add, "$this$add");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction add2 = add.add(i2, Fragment.class, bundle, str);
        Intrinsics.checkExpressionValueIsNotNull(add2, "add(containerViewId, F::class.java, args, tag)");
        return add2;
    }

    public static /* synthetic */ FragmentTransaction add$default(FragmentTransaction add, int i2, String str, Bundle bundle, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            str = null;
        }
        if ((i3 & 4) != 0) {
            bundle = null;
        }
        Intrinsics.checkParameterIsNotNull(add, "$this$add");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction add2 = add.add(i2, Fragment.class, bundle, str);
        Intrinsics.checkExpressionValueIsNotNull(add2, "add(containerViewId, F::class.java, args, tag)");
        return add2;
    }

    @NotNull
    public static final /* synthetic */ <F extends Fragment> FragmentTransaction replace(@NotNull FragmentTransaction replace, @IdRes int i2, @Nullable String str, @Nullable Bundle bundle) {
        Intrinsics.checkParameterIsNotNull(replace, "$this$replace");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction replace2 = replace.replace(i2, Fragment.class, bundle, str);
        Intrinsics.checkExpressionValueIsNotNull(replace2, "replace(containerViewId, F::class.java, args, tag)");
        return replace2;
    }

    public static /* synthetic */ FragmentTransaction replace$default(FragmentTransaction replace, int i2, String str, Bundle bundle, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            str = null;
        }
        if ((i3 & 4) != 0) {
            bundle = null;
        }
        Intrinsics.checkParameterIsNotNull(replace, "$this$replace");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction replace2 = replace.replace(i2, Fragment.class, bundle, str);
        Intrinsics.checkExpressionValueIsNotNull(replace2, "replace(containerViewId, F::class.java, args, tag)");
        return replace2;
    }

    @NotNull
    public static final /* synthetic */ <F extends Fragment> FragmentTransaction add(@NotNull FragmentTransaction add, @NotNull String tag, @Nullable Bundle bundle) {
        Intrinsics.checkParameterIsNotNull(add, "$this$add");
        Intrinsics.checkParameterIsNotNull(tag, "tag");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction add2 = add.add(Fragment.class, bundle, tag);
        Intrinsics.checkExpressionValueIsNotNull(add2, "add(F::class.java, args, tag)");
        return add2;
    }

    public static /* synthetic */ FragmentTransaction add$default(FragmentTransaction add, String tag, Bundle bundle, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            bundle = null;
        }
        Intrinsics.checkParameterIsNotNull(add, "$this$add");
        Intrinsics.checkParameterIsNotNull(tag, "tag");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentTransaction add2 = add.add(Fragment.class, bundle, tag);
        Intrinsics.checkExpressionValueIsNotNull(add2, "add(F::class.java, args, tag)");
        return add2;
    }
}
