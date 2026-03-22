package android.view;

import android.annotation.SuppressLint;
import android.view.Navigator;
import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;

@SuppressLint({"TypeParameterUnusedInFormals"})
/* loaded from: classes.dex */
public class NavigatorProvider {
    private static final HashMap<Class<?>, String> sAnnotationNames = new HashMap<>();
    private final HashMap<String, Navigator<? extends NavDestination>> mNavigators = new HashMap<>();

    @NonNull
    public static String getNameForNavigator(@NonNull Class<? extends Navigator> cls) {
        HashMap<Class<?>, String> hashMap = sAnnotationNames;
        String str = hashMap.get(cls);
        if (str == null) {
            Navigator.Name name = (Navigator.Name) cls.getAnnotation(Navigator.Name.class);
            str = name != null ? name.value() : null;
            if (!validateName(str)) {
                StringBuilder m586H = C1499a.m586H("No @Navigator.Name annotation found for ");
                m586H.append(cls.getSimpleName());
                throw new IllegalArgumentException(m586H.toString());
            }
            hashMap.put(cls, str);
        }
        return str;
    }

    private static boolean validateName(String str) {
        return (str == null || str.isEmpty()) ? false : true;
    }

    @Nullable
    public final Navigator<? extends NavDestination> addNavigator(@NonNull Navigator<? extends NavDestination> navigator) {
        return addNavigator(getNameForNavigator(navigator.getClass()), navigator);
    }

    @NonNull
    public final <T extends Navigator<?>> T getNavigator(@NonNull Class<T> cls) {
        return (T) getNavigator(getNameForNavigator(cls));
    }

    public Map<String, Navigator<? extends NavDestination>> getNavigators() {
        return this.mNavigators;
    }

    @Nullable
    @CallSuper
    public Navigator<? extends NavDestination> addNavigator(@NonNull String str, @NonNull Navigator<? extends NavDestination> navigator) {
        if (validateName(str)) {
            return this.mNavigators.put(str, navigator);
        }
        throw new IllegalArgumentException("navigator name cannot be an empty string");
    }

    @NonNull
    @CallSuper
    public <T extends Navigator<?>> T getNavigator(@NonNull String str) {
        if (validateName(str)) {
            Navigator<? extends NavDestination> navigator = this.mNavigators.get(str);
            if (navigator != null) {
                return navigator;
            }
            throw new IllegalStateException(C1499a.m639y("Could not find Navigator with name \"", str, "\". You must call NavController.addNavigator() for each navigation type."));
        }
        throw new IllegalArgumentException("navigator name cannot be an empty string");
    }
}
