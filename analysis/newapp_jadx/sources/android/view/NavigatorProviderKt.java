package android.view;

import androidx.exifinterface.media.ExifInterface;
import kotlin.Metadata;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KClass;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u0003\u001a.\u0010\u0006\u001a\u00028\u0000\"\u0010\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u00020\u00010\u0000*\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0004H\u0086\n¢\u0006\u0004\b\u0006\u0010\u0007\u001a4\u0010\u0006\u001a\u00028\u0000\"\u0010\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u00020\u00010\u0000*\u00020\u00032\f\u0010\t\u001a\b\u0012\u0004\u0012\u00028\u00000\bH\u0086\n¢\u0006\u0004\b\u0006\u0010\n\u001a>\u0010\r\u001a\u0014\u0012\u000e\b\u0001\u0012\n \f*\u0004\u0018\u00010\u00010\u0001\u0018\u00010\u0000*\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u00042\u000e\u0010\u000b\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00010\u0000H\u0086\n¢\u0006\u0004\b\r\u0010\u000e\u001a$\u0010\u0010\u001a\u00020\u000f*\u00020\u00032\u000e\u0010\u000b\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00010\u0000H\u0086\n¢\u0006\u0004\b\u0010\u0010\u0011¨\u0006\u0012"}, m5311d2 = {"Landroidx/navigation/Navigator;", "Landroidx/navigation/NavDestination;", ExifInterface.GPS_DIRECTION_TRUE, "Landroidx/navigation/NavigatorProvider;", "", "name", "get", "(Landroidx/navigation/NavigatorProvider;Ljava/lang/String;)Landroidx/navigation/Navigator;", "Lkotlin/reflect/KClass;", "clazz", "(Landroidx/navigation/NavigatorProvider;Lkotlin/reflect/KClass;)Landroidx/navigation/Navigator;", "navigator", "kotlin.jvm.PlatformType", "set", "(Landroidx/navigation/NavigatorProvider;Ljava/lang/String;Landroidx/navigation/Navigator;)Landroidx/navigation/Navigator;", "", "plusAssign", "(Landroidx/navigation/NavigatorProvider;Landroidx/navigation/Navigator;)V", "navigation-common-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavigatorProviderKt {
    @NotNull
    public static final <T extends Navigator<? extends NavDestination>> T get(@NotNull NavigatorProvider get, @NotNull String name) {
        Intrinsics.checkParameterIsNotNull(get, "$this$get");
        Intrinsics.checkParameterIsNotNull(name, "name");
        T t = (T) get.getNavigator(name);
        Intrinsics.checkExpressionValueIsNotNull(t, "getNavigator(name)");
        return t;
    }

    public static final void plusAssign(@NotNull NavigatorProvider plusAssign, @NotNull Navigator<? extends NavDestination> navigator) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        Intrinsics.checkParameterIsNotNull(navigator, "navigator");
        plusAssign.addNavigator(navigator);
    }

    @Nullable
    public static final Navigator<? extends NavDestination> set(@NotNull NavigatorProvider set, @NotNull String name, @NotNull Navigator<? extends NavDestination> navigator) {
        Intrinsics.checkParameterIsNotNull(set, "$this$set");
        Intrinsics.checkParameterIsNotNull(name, "name");
        Intrinsics.checkParameterIsNotNull(navigator, "navigator");
        return set.addNavigator(name, navigator);
    }

    @NotNull
    public static final <T extends Navigator<? extends NavDestination>> T get(@NotNull NavigatorProvider get, @NotNull KClass<T> clazz) {
        Intrinsics.checkParameterIsNotNull(get, "$this$get");
        Intrinsics.checkParameterIsNotNull(clazz, "clazz");
        T t = (T) get.getNavigator(JvmClassMappingKt.getJavaClass((KClass) clazz));
        Intrinsics.checkExpressionValueIsNotNull(t, "getNavigator(clazz.java)");
        return t;
    }
}
