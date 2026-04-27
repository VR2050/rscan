package com.google.android.gms.common.api.internal;

import android.app.Activity;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class zaa extends ActivityLifecycleObserver {
    private final WeakReference<C0009zaa> zacl;

    public zaa(Activity activity) {
        this(C0009zaa.zaa(activity));
    }

    private zaa(C0009zaa c0009zaa) {
        this.zacl = new WeakReference<>(c0009zaa);
    }

    @Override // com.google.android.gms.common.api.internal.ActivityLifecycleObserver
    public final ActivityLifecycleObserver onStopCallOnce(Runnable runnable) {
        C0009zaa c0009zaa = this.zacl.get();
        if (c0009zaa == null) {
            throw new IllegalStateException("The target activity has already been GC'd");
        }
        c0009zaa.zaa(runnable);
        return this;
    }

    /* JADX INFO: renamed from: com.google.android.gms.common.api.internal.zaa$zaa, reason: collision with other inner class name */
    static class C0009zaa extends LifecycleCallback {
        private List<Runnable> zacm;

        /* JADX INFO: Access modifiers changed from: private */
        public static C0009zaa zaa(Activity activity) {
            C0009zaa c0009zaa;
            synchronized (activity) {
                LifecycleFragment fragment = getFragment(activity);
                c0009zaa = (C0009zaa) fragment.getCallbackOrNull("LifecycleObserverOnStop", C0009zaa.class);
                if (c0009zaa == null) {
                    c0009zaa = new C0009zaa(fragment);
                }
            }
            return c0009zaa;
        }

        private C0009zaa(LifecycleFragment lifecycleFragment) {
            super(lifecycleFragment);
            this.zacm = new ArrayList();
            this.mLifecycleFragment.addCallback("LifecycleObserverOnStop", this);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final synchronized void zaa(Runnable runnable) {
            this.zacm.add(runnable);
        }

        @Override // com.google.android.gms.common.api.internal.LifecycleCallback
        public void onStop() {
            List<Runnable> list;
            synchronized (this) {
                list = this.zacm;
                this.zacm = new ArrayList();
            }
            Iterator<Runnable> it = list.iterator();
            while (it.hasNext()) {
                it.next().run();
            }
        }
    }
}
