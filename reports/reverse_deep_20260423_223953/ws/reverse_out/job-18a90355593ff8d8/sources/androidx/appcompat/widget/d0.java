package androidx.appcompat.widget;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.AssetManager;
import android.content.res.Resources;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public class d0 extends ContextWrapper {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Object f4050c = new Object();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static ArrayList f4051d;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Resources f4052a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Resources.Theme f4053b;

    private d0(Context context) {
        super(context);
        if (!q0.c()) {
            this.f4052a = new f0(this, context.getResources());
            this.f4053b = null;
            return;
        }
        q0 q0Var = new q0(this, context.getResources());
        this.f4052a = q0Var;
        Resources.Theme themeNewTheme = q0Var.newTheme();
        this.f4053b = themeNewTheme;
        themeNewTheme.setTo(context.getTheme());
    }

    private static boolean a(Context context) {
        if ((context instanceof d0) || (context.getResources() instanceof f0) || (context.getResources() instanceof q0)) {
            return false;
        }
        return q0.c();
    }

    public static Context b(Context context) {
        if (!a(context)) {
            return context;
        }
        synchronized (f4050c) {
            try {
                ArrayList arrayList = f4051d;
                if (arrayList == null) {
                    f4051d = new ArrayList();
                } else {
                    for (int size = arrayList.size() - 1; size >= 0; size--) {
                        WeakReference weakReference = (WeakReference) f4051d.get(size);
                        if (weakReference == null || weakReference.get() == null) {
                            f4051d.remove(size);
                        }
                    }
                    for (int size2 = f4051d.size() - 1; size2 >= 0; size2--) {
                        WeakReference weakReference2 = (WeakReference) f4051d.get(size2);
                        d0 d0Var = weakReference2 != null ? (d0) weakReference2.get() : null;
                        if (d0Var != null && d0Var.getBaseContext() == context) {
                            return d0Var;
                        }
                    }
                }
                d0 d0Var2 = new d0(context);
                f4051d.add(new WeakReference(d0Var2));
                return d0Var2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public AssetManager getAssets() {
        return this.f4052a.getAssets();
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public Resources getResources() {
        return this.f4052a;
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public Resources.Theme getTheme() {
        Resources.Theme theme = this.f4053b;
        return theme == null ? super.getTheme() : theme;
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public void setTheme(int i3) {
        Resources.Theme theme = this.f4053b;
        if (theme == null) {
            super.setTheme(i3);
        } else {
            theme.applyStyle(i3, true);
        }
    }
}
