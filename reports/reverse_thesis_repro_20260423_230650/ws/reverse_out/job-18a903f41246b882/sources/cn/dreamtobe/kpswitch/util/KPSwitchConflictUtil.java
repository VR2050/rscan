package cn.dreamtobe.kpswitch.util;

import android.app.Activity;
import android.view.MotionEvent;
import android.view.View;

/* JADX INFO: loaded from: classes.dex */
public class KPSwitchConflictUtil {

    public interface SwitchClickListener {
        void onClickSwitch(boolean z);
    }

    public static void attach(View panelLayout, View switchPanelKeyboardBtn, View focusView) {
        attach(panelLayout, switchPanelKeyboardBtn, focusView, (SwitchClickListener) null);
    }

    public static void attach(final View panelLayout, View switchPanelKeyboardBtn, final View focusView, final SwitchClickListener switchClickListener) {
        Activity activity = (Activity) panelLayout.getContext();
        if (switchPanelKeyboardBtn != null) {
            switchPanelKeyboardBtn.setOnClickListener(new View.OnClickListener() { // from class: cn.dreamtobe.kpswitch.util.KPSwitchConflictUtil.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    boolean switchToPanel = KPSwitchConflictUtil.switchPanelAndKeyboard(panelLayout, focusView);
                    SwitchClickListener switchClickListener2 = switchClickListener;
                    if (switchClickListener2 != null) {
                        switchClickListener2.onClickSwitch(switchToPanel);
                    }
                }
            });
        }
        if (isHandleByPlaceholder(activity)) {
            focusView.setOnTouchListener(new View.OnTouchListener() { // from class: cn.dreamtobe.kpswitch.util.KPSwitchConflictUtil.2
                @Override // android.view.View.OnTouchListener
                public boolean onTouch(View v, MotionEvent event) {
                    if (event.getAction() == 1) {
                        panelLayout.setVisibility(4);
                        return false;
                    }
                    return false;
                }
            });
        }
    }

    public static void attach(View panelLayout, View focusView, SubPanelAndTrigger... subPanelAndTriggers) {
        attach(panelLayout, focusView, (SwitchClickListener) null, subPanelAndTriggers);
    }

    public static void attach(final View panelLayout, View focusView, SwitchClickListener switchClickListener, SubPanelAndTrigger... subPanelAndTriggers) {
        Activity activity = (Activity) panelLayout.getContext();
        for (SubPanelAndTrigger subPanelAndTrigger : subPanelAndTriggers) {
            bindSubPanel(subPanelAndTrigger, subPanelAndTriggers, focusView, panelLayout, switchClickListener);
        }
        if (isHandleByPlaceholder(activity)) {
            focusView.setOnTouchListener(new View.OnTouchListener() { // from class: cn.dreamtobe.kpswitch.util.KPSwitchConflictUtil.3
                @Override // android.view.View.OnTouchListener
                public boolean onTouch(View v, MotionEvent event) {
                    if (event.getAction() == 1) {
                        panelLayout.setVisibility(4);
                        return false;
                    }
                    return false;
                }
            });
        }
    }

    public static class SubPanelAndTrigger {
        final View subPanelView;
        final View triggerView;

        public SubPanelAndTrigger(View subPanelView, View triggerView) {
            this.subPanelView = subPanelView;
            this.triggerView = triggerView;
        }
    }

    public static void showPanel(View panelLayout) {
        Activity activity = (Activity) panelLayout.getContext();
        panelLayout.setVisibility(0);
        if (activity.getCurrentFocus() != null) {
            KeyboardUtil.hideKeyboard(activity.getCurrentFocus());
        }
    }

    public static void showKeyboard(View panelLayout, View focusView) {
        Activity activity = (Activity) panelLayout.getContext();
        KeyboardUtil.showKeyboard(focusView);
        if (isHandleByPlaceholder(activity)) {
            panelLayout.setVisibility(4);
        }
    }

    public static boolean switchPanelAndKeyboard(View panelLayout, View focusView) {
        boolean switchToPanel = panelLayout.getVisibility() != 0;
        if (!switchToPanel) {
            showKeyboard(panelLayout, focusView);
        } else {
            showPanel(panelLayout);
        }
        return switchToPanel;
    }

    public static void hidePanelAndKeyboard(View panelLayout) {
        Activity activity = (Activity) panelLayout.getContext();
        View focusView = activity.getCurrentFocus();
        if (focusView != null) {
            KeyboardUtil.hideKeyboard(activity.getCurrentFocus());
            focusView.clearFocus();
        }
        panelLayout.setVisibility(8);
    }

    public static boolean isHandleByPlaceholder(boolean isFullScreen, boolean isTranslucentStatus, boolean isFitsSystem) {
        return isFullScreen || (isTranslucentStatus && !isFitsSystem);
    }

    static boolean isHandleByPlaceholder(Activity activity) {
        return isHandleByPlaceholder(ViewUtil.isFullScreen(activity), ViewUtil.isTranslucentStatus(activity), ViewUtil.isFitsSystemWindows(activity));
    }

    private static void bindSubPanel(SubPanelAndTrigger subPanelAndTrigger, final SubPanelAndTrigger[] subPanelAndTriggers, final View focusView, final View panelLayout, final SwitchClickListener switchClickListener) {
        View triggerView = subPanelAndTrigger.triggerView;
        final View boundTriggerSubPanelView = subPanelAndTrigger.subPanelView;
        triggerView.setOnClickListener(new View.OnClickListener() { // from class: cn.dreamtobe.kpswitch.util.KPSwitchConflictUtil.4
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                Boolean switchToPanel = null;
                if (panelLayout.getVisibility() == 0) {
                    if (boundTriggerSubPanelView.getVisibility() != 0) {
                        KPSwitchConflictUtil.showBoundTriggerSubPanel(boundTriggerSubPanelView, subPanelAndTriggers);
                    } else {
                        KPSwitchConflictUtil.showKeyboard(panelLayout, focusView);
                        switchToPanel = false;
                    }
                } else {
                    KPSwitchConflictUtil.showPanel(panelLayout);
                    switchToPanel = true;
                    KPSwitchConflictUtil.showBoundTriggerSubPanel(boundTriggerSubPanelView, subPanelAndTriggers);
                }
                SwitchClickListener switchClickListener2 = switchClickListener;
                if (switchClickListener2 != null && switchToPanel != null) {
                    switchClickListener2.onClickSwitch(switchToPanel.booleanValue());
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void showBoundTriggerSubPanel(View boundTriggerSubPanelView, SubPanelAndTrigger[] subPanelAndTriggers) {
        for (SubPanelAndTrigger panelAndTrigger : subPanelAndTriggers) {
            if (panelAndTrigger.subPanelView != boundTriggerSubPanelView) {
                panelAndTrigger.subPanelView.setVisibility(8);
            }
        }
        boundTriggerSubPanelView.setVisibility(0);
    }
}
