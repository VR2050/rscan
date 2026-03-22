package com.jbzd.media.movecartoons.view.keyboard;

import android.R;
import android.app.Activity;
import android.app.Application;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewTreeObserver;
import androidx.annotation.NonNull;
import com.gyf.immersionbar.Constants;

/* loaded from: classes2.dex */
public final class KeyboardWatcher implements ViewTreeObserver.OnGlobalLayoutListener, Application.ActivityLifecycleCallbacks {
    private boolean isSoftKeyboardOpened;
    private Activity mActivity;
    private View mContentView;
    private SoftKeyboardStateListener mListeners;
    private int mStatusBarHeight;

    public interface SoftKeyboardStateListener {
        void onSoftKeyboardClosed();

        void onSoftKeyboardOpened(int i2);
    }

    private KeyboardWatcher(Activity activity) {
        this.mActivity = activity;
        this.mContentView = activity.findViewById(R.id.content);
        if (Build.VERSION.SDK_INT >= 29) {
            this.mActivity.registerActivityLifecycleCallbacks(this);
        } else {
            this.mActivity.getApplication().registerActivityLifecycleCallbacks(this);
        }
        this.mContentView.getViewTreeObserver().addOnGlobalLayoutListener(this);
        int identifier = this.mActivity.getResources().getIdentifier(Constants.IMMERSION_STATUS_BAR_HEIGHT, "dimen", "android");
        if (identifier > 0) {
            this.mStatusBarHeight = this.mActivity.getResources().getDimensionPixelSize(identifier);
        }
    }

    public static KeyboardWatcher with(Activity activity) {
        return new KeyboardWatcher(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(@NonNull Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(@NonNull Activity activity) {
        Activity activity2 = this.mActivity;
        if (activity2 == activity) {
            if (Build.VERSION.SDK_INT >= 29) {
                activity2.unregisterActivityLifecycleCallbacks(this);
            } else {
                activity2.getApplication().unregisterActivityLifecycleCallbacks(this);
            }
            this.mContentView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
            this.mActivity = null;
            this.mContentView = null;
            this.mListeners = null;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(@NonNull Activity activity, @NonNull Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(@NonNull Activity activity) {
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        Rect rect = new Rect();
        this.mContentView.getWindowVisibleDisplayFrame(rect);
        int height = this.mContentView.getRootView().getHeight() - (rect.bottom - rect.top);
        if (this.isSoftKeyboardOpened || height <= this.mContentView.getRootView().getHeight() / 4) {
            if (!this.isSoftKeyboardOpened || height >= this.mContentView.getRootView().getHeight() / 4) {
                return;
            }
            this.isSoftKeyboardOpened = false;
            SoftKeyboardStateListener softKeyboardStateListener = this.mListeners;
            if (softKeyboardStateListener != null) {
                softKeyboardStateListener.onSoftKeyboardClosed();
                return;
            }
            return;
        }
        this.isSoftKeyboardOpened = true;
        if ((this.mActivity.getWindow().getAttributes().flags & 1024) != 1024) {
            SoftKeyboardStateListener softKeyboardStateListener2 = this.mListeners;
            if (softKeyboardStateListener2 != null) {
                softKeyboardStateListener2.onSoftKeyboardOpened(height - this.mStatusBarHeight);
                return;
            }
            return;
        }
        SoftKeyboardStateListener softKeyboardStateListener3 = this.mListeners;
        if (softKeyboardStateListener3 != null) {
            softKeyboardStateListener3.onSoftKeyboardOpened(height);
        }
    }

    public void setListener(SoftKeyboardStateListener softKeyboardStateListener) {
        this.mListeners = softKeyboardStateListener;
    }
}
