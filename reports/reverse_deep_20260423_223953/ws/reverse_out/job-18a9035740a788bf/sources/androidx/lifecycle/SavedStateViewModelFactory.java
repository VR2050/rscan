package androidx.lifecycle;

import android.app.Application;
import android.os.Bundle;
import androidx.lifecycle.ViewModelProvider;
import androidx.savedstate.SavedStateRegistry;
import androidx.savedstate.SavedStateRegistryOwner;
import java.lang.reflect.Constructor;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public final class SavedStateViewModelFactory extends ViewModelProvider.KeyedFactory {
    private static final Class<?>[] ANDROID_VIEWMODEL_SIGNATURE = {Application.class, SavedStateHandle.class};
    private static final Class<?>[] VIEWMODEL_SIGNATURE = {SavedStateHandle.class};
    private final Application mApplication;
    private final Bundle mDefaultArgs;
    private final ViewModelProvider.Factory mFactory;
    private final Lifecycle mLifecycle;
    private final SavedStateRegistry mSavedStateRegistry;

    public SavedStateViewModelFactory(Application application, SavedStateRegistryOwner owner) {
        this(application, owner, null);
    }

    public SavedStateViewModelFactory(Application application, SavedStateRegistryOwner owner, Bundle defaultArgs) {
        ViewModelProvider.Factory newInstanceFactory;
        this.mSavedStateRegistry = owner.getSavedStateRegistry();
        this.mLifecycle = owner.getLifecycle();
        this.mDefaultArgs = defaultArgs;
        this.mApplication = application;
        if (application != null) {
            newInstanceFactory = ViewModelProvider.AndroidViewModelFactory.getInstance(application);
        } else {
            newInstanceFactory = ViewModelProvider.NewInstanceFactory.getInstance();
        }
        this.mFactory = newInstanceFactory;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0048 A[Catch: InvocationTargetException -> 0x005c, InstantiationException -> 0x0078, IllegalAccessException -> 0x0095, TryCatch #2 {IllegalAccessException -> 0x0095, InstantiationException -> 0x0078, InvocationTargetException -> 0x005c, blocks: (B:13:0x0030, B:15:0x0034, B:17:0x0056, B:16:0x0048), top: B:28:0x0030 }] */
    /* JADX WARN: Type inference failed for: r3v11 */
    /* JADX WARN: Type inference failed for: r3v12 */
    /* JADX WARN: Type inference failed for: r3v8, types: [T extends androidx.lifecycle.ViewModel, androidx.lifecycle.ViewModel] */
    @Override // androidx.lifecycle.ViewModelProvider.KeyedFactory
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public <T extends androidx.lifecycle.ViewModel> T create(java.lang.String r8, java.lang.Class<T> r9) {
        /*
            r7 = this;
            java.lang.Class<androidx.lifecycle.AndroidViewModel> r0 = androidx.lifecycle.AndroidViewModel.class
            boolean r0 = r0.isAssignableFrom(r9)
            if (r0 == 0) goto L13
            android.app.Application r1 = r7.mApplication
            if (r1 == 0) goto L13
            java.lang.Class<?>[] r1 = androidx.lifecycle.SavedStateViewModelFactory.ANDROID_VIEWMODEL_SIGNATURE
            java.lang.reflect.Constructor r1 = findMatchingConstructor(r9, r1)
            goto L19
        L13:
            java.lang.Class<?>[] r1 = androidx.lifecycle.SavedStateViewModelFactory.VIEWMODEL_SIGNATURE
            java.lang.reflect.Constructor r1 = findMatchingConstructor(r9, r1)
        L19:
            if (r1 != 0) goto L22
            androidx.lifecycle.ViewModelProvider$Factory r2 = r7.mFactory
            androidx.lifecycle.ViewModel r2 = r2.create(r9)
            return r2
        L22:
            androidx.savedstate.SavedStateRegistry r2 = r7.mSavedStateRegistry
            androidx.lifecycle.Lifecycle r3 = r7.mLifecycle
            android.os.Bundle r4 = r7.mDefaultArgs
            androidx.lifecycle.SavedStateHandleController r2 = androidx.lifecycle.SavedStateHandleController.create(r2, r3, r8, r4)
            r3 = 0
            r4 = 1
            if (r0 == 0) goto L48
            android.app.Application r5 = r7.mApplication     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            if (r5 == 0) goto L48
            r5 = 2
            java.lang.Object[] r5 = new java.lang.Object[r5]     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            android.app.Application r6 = r7.mApplication     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            r5[r3] = r6     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            androidx.lifecycle.SavedStateHandle r3 = r2.getHandle()     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            r5[r4] = r3     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            java.lang.Object r3 = r1.newInstance(r5)     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            androidx.lifecycle.ViewModel r3 = (androidx.lifecycle.ViewModel) r3     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            goto L56
        L48:
            java.lang.Object[] r4 = new java.lang.Object[r4]     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            androidx.lifecycle.SavedStateHandle r5 = r2.getHandle()     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            r4[r3] = r5     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            java.lang.Object r3 = r1.newInstance(r4)     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            androidx.lifecycle.ViewModel r3 = (androidx.lifecycle.ViewModel) r3     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
        L56:
            java.lang.String r4 = "androidx.lifecycle.savedstate.vm.tag"
            r3.setTagIfAbsent(r4, r2)     // Catch: java.lang.reflect.InvocationTargetException -> L5c java.lang.InstantiationException -> L78 java.lang.IllegalAccessException -> L95
            return r3
        L5c:
            r3 = move-exception
            java.lang.RuntimeException r4 = new java.lang.RuntimeException
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            java.lang.String r6 = "An exception happened in constructor of "
            r5.append(r6)
            r5.append(r9)
            java.lang.String r5 = r5.toString()
            java.lang.Throwable r6 = r3.getCause()
            r4.<init>(r5, r6)
            throw r4
        L78:
            r3 = move-exception
            java.lang.RuntimeException r4 = new java.lang.RuntimeException
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            java.lang.String r6 = "A "
            r5.append(r6)
            r5.append(r9)
            java.lang.String r6 = " cannot be instantiated."
            r5.append(r6)
            java.lang.String r5 = r5.toString()
            r4.<init>(r5, r3)
            throw r4
        L95:
            r3 = move-exception
            java.lang.RuntimeException r4 = new java.lang.RuntimeException
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            java.lang.String r6 = "Failed to access "
            r5.append(r6)
            r5.append(r9)
            java.lang.String r5 = r5.toString()
            r4.<init>(r5, r3)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.SavedStateViewModelFactory.create(java.lang.String, java.lang.Class):androidx.lifecycle.ViewModel");
    }

    @Override // androidx.lifecycle.ViewModelProvider.KeyedFactory, androidx.lifecycle.ViewModelProvider.Factory
    public <T extends ViewModel> T create(Class<T> cls) {
        String canonicalName = cls.getCanonicalName();
        if (canonicalName == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        return (T) create(canonicalName, cls);
    }

    private static <T> Constructor<T> findMatchingConstructor(Class<T> cls, Class<?>[] clsArr) {
        for (Object obj : cls.getConstructors()) {
            Constructor<T> constructor = (Constructor<T>) obj;
            if (Arrays.equals(clsArr, constructor.getParameterTypes())) {
                return constructor;
            }
        }
        return null;
    }

    @Override // androidx.lifecycle.ViewModelProvider.OnRequeryFactory
    void onRequery(ViewModel viewModel) {
        SavedStateHandleController.attachHandleIfNeeded(viewModel, this.mSavedStateRegistry, this.mLifecycle);
    }
}
