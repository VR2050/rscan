package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.inputmethod.InputMethodManager;
import cn.dreamtobe.kpswitch.IPanelHeightTarget;
import cn.dreamtobe.kpswitch.util.KPSwitchConflictUtil;
import com.blankj.utilcode.util.Utils;
import java.lang.reflect.Method;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class KeyboardUtils {
    private static int LAST_SAVE_KEYBOARD_HEIGHT = 0;
    private static int MAX_PANEL_HEIGHT = 0;
    private static int MIN_PANEL_HEIGHT = 0;
    private static int MIN_KEYBOARD_HEIGHT = 0;

    public interface OnKeyboardShowingListener {
        void onKeyboardShowing(boolean z);
    }

    public static void showKeyboard(View view) {
        view.requestFocus();
        InputMethodManager inputManager = (InputMethodManager) view.getContext().getSystemService("input_method");
        inputManager.showSoftInput(view, 0);
    }

    public static void hideKeyboard(View view) {
        InputMethodManager imm = (InputMethodManager) view.getContext().getSystemService("input_method");
        imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean saveKeyboardHeight(Context context, int keyboardHeight) {
        if (LAST_SAVE_KEYBOARD_HEIGHT == keyboardHeight || keyboardHeight < 0) {
            return false;
        }
        LAST_SAVE_KEYBOARD_HEIGHT = keyboardHeight;
        Log.d("KeyBordUtil", String.format("save keyboard: %d", Integer.valueOf(keyboardHeight)));
        return KeyBoardSharedPreferences.save(context, keyboardHeight);
    }

    public static int getKeyboardHeight(Context context) {
        if (LAST_SAVE_KEYBOARD_HEIGHT == 0) {
            LAST_SAVE_KEYBOARD_HEIGHT = KeyBoardSharedPreferences.get(context, getMinPanelHeight(context.getResources()));
        }
        return LAST_SAVE_KEYBOARD_HEIGHT;
    }

    public static int getValidPanelHeight(Context context) {
        int maxPanelHeight = getMaxPanelHeight(context.getResources());
        int minPanelHeight = getMinPanelHeight(context.getResources());
        int validPanelHeight = getKeyboardHeight(context);
        return Math.min(maxPanelHeight, Math.max(minPanelHeight, validPanelHeight));
    }

    public static int getMaxPanelHeight(Resources res) {
        if (MAX_PANEL_HEIGHT == 0) {
            MAX_PANEL_HEIGHT = res.getDimensionPixelSize(R.dimen.max_panel_height);
        }
        return MAX_PANEL_HEIGHT;
    }

    public static int getMinPanelHeight(Resources res) {
        if (MIN_PANEL_HEIGHT == 0) {
            MIN_PANEL_HEIGHT = res.getDimensionPixelSize(R.dimen.min_panel_height);
        }
        return MIN_PANEL_HEIGHT;
    }

    public static int getMinKeyboardHeight(Context context) {
        if (MIN_KEYBOARD_HEIGHT == 0) {
            MIN_KEYBOARD_HEIGHT = context.getResources().getDimensionPixelSize(R.dimen.min_keyboard_height);
        }
        return MIN_KEYBOARD_HEIGHT;
    }

    public static ViewTreeObserver.OnGlobalLayoutListener attach(Activity activity, IPanelHeightTarget target, OnKeyboardShowingListener lis) {
        int screenHeight;
        ViewGroup contentView = (ViewGroup) activity.findViewById(android.R.id.content);
        boolean isFullScreen = ViewUtil.isFullScreen(activity);
        boolean isTranslucentStatus = ViewUtil.isTranslucentStatus(activity);
        boolean isFitSystemWindows = ViewUtil.isFitsSystemWindows(activity);
        Display display = activity.getWindowManager().getDefaultDisplay();
        if (Build.VERSION.SDK_INT >= 13) {
            Point screenSize = new Point();
            display.getSize(screenSize);
            int screenHeight2 = screenSize.y;
            screenHeight = screenHeight2;
        } else {
            int screenHeight3 = display.getHeight();
            screenHeight = screenHeight3;
        }
        ViewTreeObserver.OnGlobalLayoutListener globalLayoutListener = new KeyboardStatusListener(isFullScreen, isTranslucentStatus, isFitSystemWindows, contentView, target, lis, screenHeight);
        contentView.getViewTreeObserver().addOnGlobalLayoutListener(globalLayoutListener);
        return globalLayoutListener;
    }

    public static ViewTreeObserver.OnGlobalLayoutListener attach(Activity activity, IPanelHeightTarget target) {
        return attach(activity, target, null);
    }

    public static void detach(Activity activity, ViewTreeObserver.OnGlobalLayoutListener l) {
        ViewGroup contentView = (ViewGroup) activity.findViewById(android.R.id.content);
        if (Build.VERSION.SDK_INT >= 16) {
            contentView.getViewTreeObserver().removeOnGlobalLayoutListener(l);
        } else {
            contentView.getViewTreeObserver().removeGlobalOnLayoutListener(l);
        }
    }

    private static class KeyboardStatusListener implements ViewTreeObserver.OnGlobalLayoutListener {
        private static final String TAG = "KeyboardStatusListener";
        private final ViewGroup contentView;
        private final boolean isFitSystemWindows;
        private final boolean isFullScreen;
        private final boolean isTranslucentStatus;
        private final OnKeyboardShowingListener keyboardShowingListener;
        private boolean lastKeyboardShowing;
        private int maxOverlayLayoutHeight;
        private final IPanelHeightTarget panelHeightTarget;
        private final int screenHeight;
        private final int statusBarHeight;
        private int previousDisplayHeight = 0;
        private boolean isOverlayLayoutDisplayHContainStatusBar = false;
        private boolean hasNavigationBar = checkDeviceHasNavigationBar();

        KeyboardStatusListener(boolean isFullScreen, boolean isTranslucentStatus, boolean isFitSystemWindows, ViewGroup contentView, IPanelHeightTarget panelHeightTarget, OnKeyboardShowingListener listener, int screenHeight) {
            this.contentView = contentView;
            this.panelHeightTarget = panelHeightTarget;
            this.isFullScreen = isFullScreen;
            this.isTranslucentStatus = isTranslucentStatus;
            this.isFitSystemWindows = isFitSystemWindows;
            this.statusBarHeight = StatusBarHeightUtil.getStatusBarHeight(contentView.getContext());
            this.keyboardShowingListener = listener;
            this.screenHeight = screenHeight;
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            int displayHeight;
            View userRootView = this.contentView.getChildAt(0);
            View actionBarOverlayLayout = (View) this.contentView.getParent();
            Rect r = new Rect();
            if (this.isTranslucentStatus) {
                actionBarOverlayLayout.getWindowVisibleDisplayFrame(r);
                int overlayLayoutDisplayHeight = r.bottom - r.top;
                if (!this.isOverlayLayoutDisplayHContainStatusBar) {
                    this.isOverlayLayoutDisplayHContainStatusBar = overlayLayoutDisplayHeight == this.screenHeight;
                }
                if (!this.isOverlayLayoutDisplayHContainStatusBar) {
                    displayHeight = this.statusBarHeight + overlayLayoutDisplayHeight;
                } else {
                    displayHeight = overlayLayoutDisplayHeight;
                }
            } else if (userRootView != null) {
                userRootView.getWindowVisibleDisplayFrame(r);
                displayHeight = r.bottom - r.top;
            } else {
                Log.w("KeyBordUtil", "user root view not ready so ignore global layout changed!");
                displayHeight = -1;
            }
            if (displayHeight == -1) {
                return;
            }
            calculateKeyboardHeight(displayHeight);
            calculateKeyboardShowing(displayHeight);
            this.previousDisplayHeight = displayHeight;
        }

        private void calculateKeyboardHeight(int displayHeight) {
            int keyboardHeight;
            int validPanelHeight;
            if (this.previousDisplayHeight == 0) {
                this.previousDisplayHeight = displayHeight;
                this.panelHeightTarget.refreshHeight(KeyboardUtils.getValidPanelHeight(getContext()));
                return;
            }
            if (KPSwitchConflictUtil.isHandleByPlaceholder(this.isFullScreen, this.isTranslucentStatus, this.isFitSystemWindows)) {
                View actionBarOverlayLayout = (View) this.contentView.getParent();
                keyboardHeight = actionBarOverlayLayout.getHeight() - displayHeight;
                Log.d(TAG, String.format("action bar over layout %d display height: %d", Integer.valueOf(((View) this.contentView.getParent()).getHeight()), Integer.valueOf(displayHeight)));
            } else {
                keyboardHeight = Math.abs(displayHeight - this.previousDisplayHeight);
            }
            if (keyboardHeight <= KeyboardUtils.getMinKeyboardHeight(getContext())) {
                return;
            }
            Log.d(TAG, String.format("pre display height: %d display height: %d keyboard: %d ", Integer.valueOf(this.previousDisplayHeight), Integer.valueOf(displayHeight), Integer.valueOf(keyboardHeight)));
            if (keyboardHeight != this.statusBarHeight) {
                boolean changed = KeyboardUtils.saveKeyboardHeight(getContext(), keyboardHeight);
                if (changed && this.panelHeightTarget.getHeight() != (validPanelHeight = KeyboardUtils.getValidPanelHeight(getContext()))) {
                    this.panelHeightTarget.refreshHeight(validPanelHeight);
                    return;
                }
                return;
            }
            Log.w(TAG, String.format("On global layout change get keyboard height just equal statusBar height %d", Integer.valueOf(keyboardHeight)));
        }

        private void calculateKeyboardShowing(int displayHeight) {
            boolean isKeyboardShowing;
            boolean isKeyboardShowing2;
            View actionBarOverlayLayout = (View) this.contentView.getParent();
            int actionBarOverlayLayoutHeight = actionBarOverlayLayout.getHeight() - actionBarOverlayLayout.getPaddingTop();
            if (KPSwitchConflictUtil.isHandleByPlaceholder(this.isFullScreen, this.isTranslucentStatus, this.isFitSystemWindows)) {
                if (!this.isTranslucentStatus && actionBarOverlayLayoutHeight - displayHeight == this.statusBarHeight) {
                    isKeyboardShowing2 = this.lastKeyboardShowing;
                } else {
                    isKeyboardShowing2 = actionBarOverlayLayoutHeight > displayHeight;
                }
            } else {
                int phoneDisplayHeight = this.contentView.getResources().getDisplayMetrics().heightPixels;
                if (!this.isTranslucentStatus && this.hasNavigationBar && phoneDisplayHeight == actionBarOverlayLayoutHeight) {
                    Log.w(TAG, String.format("skip the keyboard status calculate, the current activity is paused. and phone-display-height %d, root-height+actionbar-height %d", Integer.valueOf(phoneDisplayHeight), Integer.valueOf(actionBarOverlayLayoutHeight)));
                    return;
                }
                int i = this.maxOverlayLayoutHeight;
                if (i == 0) {
                    isKeyboardShowing = this.lastKeyboardShowing;
                } else {
                    isKeyboardShowing = displayHeight < i - KeyboardUtils.getMinKeyboardHeight(getContext());
                }
                this.maxOverlayLayoutHeight = Math.max(this.maxOverlayLayoutHeight, actionBarOverlayLayoutHeight);
                isKeyboardShowing2 = isKeyboardShowing;
            }
            boolean isKeyboardShowing3 = this.lastKeyboardShowing;
            if (isKeyboardShowing3 != isKeyboardShowing2) {
                Log.d(TAG, String.format("displayHeight %d actionBarOverlayLayoutHeight %d keyboard status change: %B", Integer.valueOf(displayHeight), Integer.valueOf(actionBarOverlayLayoutHeight), Boolean.valueOf(isKeyboardShowing2)));
                this.panelHeightTarget.onKeyboardShowing(isKeyboardShowing2);
                OnKeyboardShowingListener onKeyboardShowingListener = this.keyboardShowingListener;
                if (onKeyboardShowingListener != null) {
                    onKeyboardShowingListener.onKeyboardShowing(isKeyboardShowing2);
                }
            }
            this.lastKeyboardShowing = isKeyboardShowing2;
        }

        private Context getContext() {
            return this.contentView.getContext();
        }

        private boolean checkDeviceHasNavigationBar() {
            boolean hasNavigationBar = false;
            Resources rs = Utils.getApp().getResources();
            int id = rs.getIdentifier("config_showNavigationBar", "bool", "android");
            if (id > 0) {
                hasNavigationBar = rs.getBoolean(id);
            }
            try {
                Class<?> cls = Class.forName("android.os.SystemProperties");
                Method m = cls.getMethod("get", String.class);
                String navBarOverride = (String) m.invoke(cls, "qemu.hw.mainkeys");
                if ("1".equals(navBarOverride)) {
                    return false;
                }
                if ("0".equals(navBarOverride)) {
                    return true;
                }
                return hasNavigationBar;
            } catch (Exception e) {
                return hasNavigationBar;
            }
        }
    }
}
