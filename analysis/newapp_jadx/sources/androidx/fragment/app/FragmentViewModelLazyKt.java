package androidx.fragment.app;

import androidx.annotation.MainThread;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import kotlin.Lazy;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KClass;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u001aH\u0010\t\u001a\b\u0012\u0004\u0012\u00028\u00000\b\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\u000e\b\n\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00040\u00032\u0010\b\n\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0003H\u0087\b¢\u0006\u0004\b\t\u0010\n\u001a8\u0010\u000b\u001a\b\u0012\u0004\u0012\u00028\u00000\b\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\u0010\b\n\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0003H\u0087\b¢\u0006\u0004\b\u000b\u0010\f\u001aQ\u0010\u0011\u001a\b\u0012\u0004\u0012\u00028\u00000\b\"\b\b\u0000\u0010\u0001*\u00020\u0000*\u00020\u00022\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00028\u00000\r2\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u000f0\u00032\u0010\b\u0002\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0003H\u0007¢\u0006\u0004\b\u0011\u0010\u0012¨\u0006\u0013"}, m5311d2 = {"Landroidx/lifecycle/ViewModel;", "VM", "Landroidx/fragment/app/Fragment;", "Lkotlin/Function0;", "Landroidx/lifecycle/ViewModelStoreOwner;", "ownerProducer", "Landroidx/lifecycle/ViewModelProvider$Factory;", "factoryProducer", "Lkotlin/Lazy;", "viewModels", "(Landroidx/fragment/app/Fragment;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;", "activityViewModels", "(Landroidx/fragment/app/Fragment;Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;", "Lkotlin/reflect/KClass;", "viewModelClass", "Landroidx/lifecycle/ViewModelStore;", "storeProducer", "createViewModelLazy", "(Landroidx/fragment/app/Fragment;Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;", "fragment-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class FragmentViewModelLazyKt {
    @MainThread
    @NotNull
    public static final /* synthetic */ <VM extends ViewModel> Lazy<VM> activityViewModels(@NotNull Fragment activityViewModels, @Nullable Function0<? extends ViewModelProvider.Factory> function0) {
        Intrinsics.checkParameterIsNotNull(activityViewModels, "$this$activityViewModels");
        Intrinsics.reifiedOperationMarker(4, "VM");
        KClass orCreateKotlinClass = Reflection.getOrCreateKotlinClass(ViewModel.class);
        FragmentViewModelLazyKt$activityViewModels$1 fragmentViewModelLazyKt$activityViewModels$1 = new FragmentViewModelLazyKt$activityViewModels$1(activityViewModels);
        if (function0 == null) {
            function0 = new FragmentViewModelLazyKt$activityViewModels$2(activityViewModels);
        }
        return createViewModelLazy(activityViewModels, orCreateKotlinClass, fragmentViewModelLazyKt$activityViewModels$1, function0);
    }

    public static /* synthetic */ Lazy activityViewModels$default(Fragment activityViewModels, Function0 function0, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            function0 = null;
        }
        Intrinsics.checkParameterIsNotNull(activityViewModels, "$this$activityViewModels");
        Intrinsics.reifiedOperationMarker(4, "VM");
        KClass orCreateKotlinClass = Reflection.getOrCreateKotlinClass(ViewModel.class);
        FragmentViewModelLazyKt$activityViewModels$1 fragmentViewModelLazyKt$activityViewModels$1 = new FragmentViewModelLazyKt$activityViewModels$1(activityViewModels);
        if (function0 == null) {
            function0 = new FragmentViewModelLazyKt$activityViewModels$2(activityViewModels);
        }
        return createViewModelLazy(activityViewModels, orCreateKotlinClass, fragmentViewModelLazyKt$activityViewModels$1, function0);
    }

    @MainThread
    @NotNull
    public static final <VM extends ViewModel> Lazy<VM> createViewModelLazy(@NotNull final Fragment createViewModelLazy, @NotNull KClass<VM> viewModelClass, @NotNull Function0<? extends ViewModelStore> storeProducer, @Nullable Function0<? extends ViewModelProvider.Factory> function0) {
        Intrinsics.checkParameterIsNotNull(createViewModelLazy, "$this$createViewModelLazy");
        Intrinsics.checkParameterIsNotNull(viewModelClass, "viewModelClass");
        Intrinsics.checkParameterIsNotNull(storeProducer, "storeProducer");
        if (function0 == null) {
            function0 = new Function0<ViewModelProvider.Factory>() { // from class: androidx.fragment.app.FragmentViewModelLazyKt$createViewModelLazy$factoryPromise$1
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final ViewModelProvider.Factory invoke() {
                    ViewModelProvider.Factory defaultViewModelProviderFactory = Fragment.this.getDefaultViewModelProviderFactory();
                    Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "defaultViewModelProviderFactory");
                    return defaultViewModelProviderFactory;
                }
            };
        }
        return new ViewModelLazy(viewModelClass, storeProducer, function0);
    }

    public static /* synthetic */ Lazy createViewModelLazy$default(Fragment fragment, KClass kClass, Function0 function0, Function0 function02, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function02 = null;
        }
        return createViewModelLazy(fragment, kClass, function0, function02);
    }

    @MainThread
    @NotNull
    public static final /* synthetic */ <VM extends ViewModel> Lazy<VM> viewModels(@NotNull Fragment viewModels, @NotNull Function0<? extends ViewModelStoreOwner> ownerProducer, @Nullable Function0<? extends ViewModelProvider.Factory> function0) {
        Intrinsics.checkParameterIsNotNull(viewModels, "$this$viewModels");
        Intrinsics.checkParameterIsNotNull(ownerProducer, "ownerProducer");
        Intrinsics.reifiedOperationMarker(4, "VM");
        return createViewModelLazy(viewModels, Reflection.getOrCreateKotlinClass(ViewModel.class), new FragmentViewModelLazyKt$viewModels$2(ownerProducer), function0);
    }

    public static /* synthetic */ Lazy viewModels$default(final Fragment viewModels, Function0 ownerProducer, Function0 function0, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            ownerProducer = new Function0<Fragment>() { // from class: androidx.fragment.app.FragmentViewModelLazyKt$viewModels$1
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final Fragment invoke() {
                    return Fragment.this;
                }
            };
        }
        if ((i2 & 2) != 0) {
            function0 = null;
        }
        Intrinsics.checkParameterIsNotNull(viewModels, "$this$viewModels");
        Intrinsics.checkParameterIsNotNull(ownerProducer, "ownerProducer");
        Intrinsics.reifiedOperationMarker(4, "VM");
        return createViewModelLazy(viewModels, Reflection.getOrCreateKotlinClass(ViewModel.class), new FragmentViewModelLazyKt$viewModels$2(ownerProducer), function0);
    }
}
