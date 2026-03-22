package android.view.fragment;

import android.view.NavDestinationBuilder;
import android.view.NavDestinationDsl;
import android.view.fragment.DialogFragmentNavigator;
import androidx.annotation.IdRes;
import androidx.fragment.app.DialogFragment;
import kotlin.Metadata;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KClass;
import org.jetbrains.annotations.NotNull;

@NavDestinationDsl
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\b\u0007\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B)\u0012\u0006\u0010\n\u001a\u00020\t\u0012\b\b\u0001\u0010\f\u001a\u00020\u000b\u0012\u000e\u0010\u0007\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00060\u0005¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004R\u001e\u0010\u0007\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00060\u00058\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000f"}, m5311d2 = {"Landroidx/navigation/fragment/DialogFragmentNavigatorDestinationBuilder;", "Landroidx/navigation/NavDestinationBuilder;", "Landroidx/navigation/fragment/DialogFragmentNavigator$Destination;", "build", "()Landroidx/navigation/fragment/DialogFragmentNavigator$Destination;", "Lkotlin/reflect/KClass;", "Landroidx/fragment/app/DialogFragment;", "fragmentClass", "Lkotlin/reflect/KClass;", "Landroidx/navigation/fragment/DialogFragmentNavigator;", "navigator", "", "id", "<init>", "(Landroidx/navigation/fragment/DialogFragmentNavigator;ILkotlin/reflect/KClass;)V", "navigation-fragment-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class DialogFragmentNavigatorDestinationBuilder extends NavDestinationBuilder<DialogFragmentNavigator.Destination> {
    private final KClass<? extends DialogFragment> fragmentClass;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DialogFragmentNavigatorDestinationBuilder(@NotNull DialogFragmentNavigator navigator, @IdRes int i2, @NotNull KClass<? extends DialogFragment> fragmentClass) {
        super(navigator, i2);
        Intrinsics.checkParameterIsNotNull(navigator, "navigator");
        Intrinsics.checkParameterIsNotNull(fragmentClass, "fragmentClass");
        this.fragmentClass = fragmentClass;
    }

    @Override // android.view.NavDestinationBuilder
    @NotNull
    public DialogFragmentNavigator.Destination build() {
        DialogFragmentNavigator.Destination destination = (DialogFragmentNavigator.Destination) super.build();
        destination.setClassName(JvmClassMappingKt.getJavaClass((KClass) this.fragmentClass).getName());
        return destination;
    }
}
