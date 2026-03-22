package com.gyf.immersionbar;

import android.app.Application;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class NavigationBarObserver extends ContentObserver {
    private Application mApplication;
    private Boolean mIsRegister;
    private ArrayList<OnNavigationBarListener> mListeners;

    public static class NavigationBarObserverInstance {
        private static final NavigationBarObserver INSTANCE = new NavigationBarObserver();

        private NavigationBarObserverInstance() {
        }
    }

    public static NavigationBarObserver getInstance() {
        return NavigationBarObserverInstance.INSTANCE;
    }

    public void addOnNavigationBarListener(OnNavigationBarListener onNavigationBarListener) {
        if (onNavigationBarListener == null) {
            return;
        }
        if (this.mListeners == null) {
            this.mListeners = new ArrayList<>();
        }
        if (this.mListeners.contains(onNavigationBarListener)) {
            return;
        }
        this.mListeners.add(onNavigationBarListener);
    }

    @Override // android.database.ContentObserver
    public void onChange(boolean z) {
        ArrayList<OnNavigationBarListener> arrayList;
        super.onChange(z);
        Application application = this.mApplication;
        if (application == null || application.getContentResolver() == null || (arrayList = this.mListeners) == null || arrayList.isEmpty()) {
            return;
        }
        int i2 = OSUtils.isMIUI() ? Settings.Global.getInt(this.mApplication.getContentResolver(), Constants.IMMERSION_MIUI_NAVIGATION_BAR_HIDE_SHOW, 0) : OSUtils.isEMUI() ? !OSUtils.isEMUI3_x() ? Settings.Global.getInt(this.mApplication.getContentResolver(), Constants.IMMERSION_EMUI_NAVIGATION_BAR_HIDE_SHOW, 0) : Settings.System.getInt(this.mApplication.getContentResolver(), Constants.IMMERSION_EMUI_NAVIGATION_BAR_HIDE_SHOW, 0) : 0;
        Iterator<OnNavigationBarListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            OnNavigationBarListener next = it.next();
            boolean z2 = true;
            if (i2 == 1) {
                z2 = false;
            }
            next.onNavigationBarChange(z2);
        }
    }

    public void register(Application application) {
        this.mApplication = application;
        if (application == null || application.getContentResolver() == null || this.mIsRegister.booleanValue()) {
            return;
        }
        Uri uri = null;
        if (OSUtils.isMIUI()) {
            uri = Settings.Global.getUriFor(Constants.IMMERSION_MIUI_NAVIGATION_BAR_HIDE_SHOW);
        } else if (OSUtils.isEMUI()) {
            uri = !OSUtils.isEMUI3_x() ? Settings.Global.getUriFor(Constants.IMMERSION_EMUI_NAVIGATION_BAR_HIDE_SHOW) : Settings.System.getUriFor(Constants.IMMERSION_EMUI_NAVIGATION_BAR_HIDE_SHOW);
        }
        if (uri != null) {
            this.mApplication.getContentResolver().registerContentObserver(uri, true, this);
            this.mIsRegister = Boolean.TRUE;
        }
    }

    public void removeOnNavigationBarListener(OnNavigationBarListener onNavigationBarListener) {
        ArrayList<OnNavigationBarListener> arrayList;
        if (onNavigationBarListener == null || (arrayList = this.mListeners) == null) {
            return;
        }
        arrayList.remove(onNavigationBarListener);
    }

    private NavigationBarObserver() {
        super(new Handler(Looper.getMainLooper()));
        this.mIsRegister = Boolean.FALSE;
    }
}
