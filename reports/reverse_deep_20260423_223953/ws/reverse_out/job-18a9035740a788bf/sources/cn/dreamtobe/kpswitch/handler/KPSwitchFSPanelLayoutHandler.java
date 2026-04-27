package cn.dreamtobe.kpswitch.handler;

import android.view.View;
import android.view.Window;
import cn.dreamtobe.kpswitch.IFSPanelConflictLayout;
import cn.dreamtobe.kpswitch.util.KeyboardUtil;

/* JADX INFO: loaded from: classes.dex */
public class KPSwitchFSPanelLayoutHandler implements IFSPanelConflictLayout {
    private boolean isKeyboardShowing;
    private final View panelLayout;
    private View recordedFocusView;

    public KPSwitchFSPanelLayoutHandler(View panelLayout) {
        this.panelLayout = panelLayout;
    }

    public void onKeyboardShowing(boolean showing) {
        this.isKeyboardShowing = showing;
        if (!showing && this.panelLayout.getVisibility() == 4) {
            this.panelLayout.setVisibility(8);
        }
        if (!showing && this.recordedFocusView != null) {
            restoreFocusView();
            this.recordedFocusView = null;
        }
    }

    @Override // cn.dreamtobe.kpswitch.IFSPanelConflictLayout
    public void recordKeyboardStatus(Window window) {
        View focusView = window.getCurrentFocus();
        if (focusView == null) {
            return;
        }
        if (this.isKeyboardShowing) {
            saveFocusView(focusView);
        } else {
            focusView.clearFocus();
        }
    }

    private void saveFocusView(View focusView) {
        this.recordedFocusView = focusView;
        focusView.clearFocus();
        this.panelLayout.setVisibility(8);
    }

    private void restoreFocusView() {
        this.panelLayout.setVisibility(4);
        KeyboardUtil.showKeyboard(this.recordedFocusView);
    }
}
