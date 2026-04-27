package cn.dreamtobe.kpswitch.handler;

import android.app.Activity;
import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import cn.dreamtobe.kpswitch.IPanelConflictLayout;
import cn.dreamtobe.kpswitch.util.KeyboardUtil;
import cn.dreamtobe.kpswitch.util.StatusBarHeightUtil;
import cn.dreamtobe.kpswitch.util.ViewUtil;

/* JADX INFO: loaded from: classes.dex */
public class KPSwitchRootLayoutHandler {
    private static final String TAG = "KPSRootLayoutHandler";
    private final boolean mIsTranslucentStatus;
    private int mOldHeight = -1;
    private IPanelConflictLayout mPanelLayout;
    private final int mStatusBarHeight;
    private final View mTargetRootView;

    public KPSwitchRootLayoutHandler(View rootView) {
        this.mTargetRootView = rootView;
        this.mStatusBarHeight = StatusBarHeightUtil.getStatusBarHeight(rootView.getContext());
        Activity activity = (Activity) rootView.getContext();
        this.mIsTranslucentStatus = ViewUtil.isTranslucentStatus(activity);
    }

    public void handleBeforeMeasure(int width, int height) {
        if (this.mIsTranslucentStatus && Build.VERSION.SDK_INT >= 16 && this.mTargetRootView.getFitsSystemWindows()) {
            Rect rect = new Rect();
            this.mTargetRootView.getWindowVisibleDisplayFrame(rect);
            height = rect.bottom - rect.top;
        }
        Log.d(TAG, "onMeasure, width: " + width + " height: " + height);
        if (height < 0) {
            return;
        }
        int i = this.mOldHeight;
        if (i < 0) {
            this.mOldHeight = height;
            return;
        }
        int offset = i - height;
        if (offset == 0) {
            Log.d(TAG, "" + offset + " == 0 break;");
            return;
        }
        if (Math.abs(offset) == this.mStatusBarHeight) {
            Log.w(TAG, String.format("offset just equal statusBar height %d", Integer.valueOf(offset)));
            return;
        }
        this.mOldHeight = height;
        IPanelConflictLayout panel = getPanelLayout(this.mTargetRootView);
        if (panel == null) {
            Log.w(TAG, "can't find the valid panel conflict layout, give up!");
            return;
        }
        if (Math.abs(offset) < KeyboardUtil.getMinKeyboardHeight(this.mTargetRootView.getContext())) {
            Log.w(TAG, "system bottom-menu-bar(such as HuaWei Mate7) causes layout changed");
            return;
        }
        if (offset > 0) {
            panel.handleHide();
        } else if (panel.isKeyboardShowing() && panel.isVisible()) {
            panel.handleShow();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private IPanelConflictLayout getPanelLayout(View view) {
        IPanelConflictLayout iPanelConflictLayout = this.mPanelLayout;
        if (iPanelConflictLayout != null) {
            return iPanelConflictLayout;
        }
        if (view instanceof IPanelConflictLayout) {
            IPanelConflictLayout iPanelConflictLayout2 = (IPanelConflictLayout) view;
            this.mPanelLayout = iPanelConflictLayout2;
            return iPanelConflictLayout2;
        }
        if (view instanceof ViewGroup) {
            for (int i = 0; i < ((ViewGroup) view).getChildCount(); i++) {
                IPanelConflictLayout v = getPanelLayout(((ViewGroup) view).getChildAt(i));
                if (v != null) {
                    this.mPanelLayout = v;
                    return v;
                }
            }
            return null;
        }
        return null;
    }
}
