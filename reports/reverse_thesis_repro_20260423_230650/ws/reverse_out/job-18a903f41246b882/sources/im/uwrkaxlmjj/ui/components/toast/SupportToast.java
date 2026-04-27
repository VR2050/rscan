package im.uwrkaxlmjj.ui.components.toast;

import android.R;
import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.ArrayMap;
import android.view.WindowManager;
import android.widget.Toast;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;

/* JADX INFO: loaded from: classes5.dex */
public final class SupportToast extends BaseToast {
    private final ToastHelper mToastHelper;

    public SupportToast(Context context) {
        super(context);
        this.mToastHelper = new ToastHelper(this, context);
    }

    @Override // android.widget.Toast
    public void show() {
        this.mToastHelper.show();
    }

    @Override // android.widget.Toast
    public void cancel() {
        this.mToastHelper.cancel();
    }

    private static final class ToastHelper extends Handler {
        private boolean isShow;
        private final String mPackageName;
        private final Toast mToast;
        private final WindowHelper mWindowHelper;

        ToastHelper(Toast toast, Context context) {
            super(Looper.getMainLooper());
            this.mToast = toast;
            this.mPackageName = context.getPackageName();
            this.mWindowHelper = WindowHelper.register(this, context);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            cancel();
        }

        void show() {
            if (!this.isShow) {
                WindowManager.LayoutParams params = new WindowManager.LayoutParams();
                params.height = -2;
                params.width = -2;
                params.format = -3;
                params.windowAnimations = R.style.Animation.Toast;
                params.flags = 152;
                params.packageName = this.mPackageName;
                params.gravity = this.mToast.getGravity();
                params.x = this.mToast.getXOffset();
                params.y = this.mToast.getYOffset();
                try {
                    this.mWindowHelper.getWindowManager().addView(this.mToast.getView(), params);
                    this.isShow = true;
                    sendEmptyMessageDelayed(0, this.mToast.getDuration() == 1 ? 3500L : AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                } catch (WindowManager.BadTokenException e) {
                } catch (IllegalStateException e2) {
                } catch (NullPointerException e3) {
                }
            }
        }

        void cancel() {
            removeMessages(0);
            if (this.isShow) {
                try {
                    this.mWindowHelper.getWindowManager().removeViewImmediate(this.mToast.getView());
                } catch (IllegalArgumentException e) {
                } catch (NullPointerException e2) {
                }
                this.isShow = false;
            }
        }
    }

    private static final class WindowHelper implements Application.ActivityLifecycleCallbacks {
        private final ArrayMap<String, Activity> mActivitySet = new ArrayMap<>();
        private String mCurrentTag;
        private final ToastHelper mToastHelper;

        private WindowHelper(ToastHelper toast) {
            this.mToastHelper = toast;
        }

        static WindowHelper register(ToastHelper toast, Context context) {
            WindowHelper window = new WindowHelper(toast);
            if (context instanceof Application) {
                ((Application) context).registerActivityLifecycleCallbacks(window);
            }
            return window;
        }

        WindowManager getWindowManager() throws NullPointerException {
            Activity activity;
            String str = this.mCurrentTag;
            if (str != null && (activity = this.mActivitySet.get(str)) != null) {
                return getWindowManagerObject(activity);
            }
            throw null;
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            String objectTag = getObjectTag(activity);
            this.mCurrentTag = objectTag;
            this.mActivitySet.put(objectTag, activity);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
            this.mCurrentTag = getObjectTag(activity);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
            this.mCurrentTag = getObjectTag(activity);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            this.mToastHelper.cancel();
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
            this.mActivitySet.remove(getObjectTag(activity));
            if (getObjectTag(activity).equals(this.mCurrentTag)) {
                this.mCurrentTag = null;
            }
        }

        private static String getObjectTag(Object object) {
            return object.getClass().getName() + Integer.toHexString(object.hashCode());
        }

        private static WindowManager getWindowManagerObject(Activity activity) {
            return (WindowManager) activity.getSystemService("window");
        }
    }
}
