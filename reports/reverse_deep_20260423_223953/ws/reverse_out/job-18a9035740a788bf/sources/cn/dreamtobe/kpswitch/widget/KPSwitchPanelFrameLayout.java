package cn.dreamtobe.kpswitch.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import cn.dreamtobe.kpswitch.IPanelConflictLayout;
import cn.dreamtobe.kpswitch.IPanelHeightTarget;
import cn.dreamtobe.kpswitch.handler.KPSwitchPanelLayoutHandler;

/* JADX INFO: loaded from: classes.dex */
public class KPSwitchPanelFrameLayout extends FrameLayout implements IPanelHeightTarget, IPanelConflictLayout {
    private KPSwitchPanelLayoutHandler panelLayoutHandler;

    public KPSwitchPanelFrameLayout(Context context) {
        super(context);
        init(null);
    }

    public KPSwitchPanelFrameLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(attrs);
    }

    public KPSwitchPanelFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(attrs);
    }

    public KPSwitchPanelFrameLayout(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        init(attrs);
    }

    private void init(AttributeSet attrs) {
        this.panelLayoutHandler = new KPSwitchPanelLayoutHandler(this, attrs);
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        if (this.panelLayoutHandler.filterSetVisibility(visibility)) {
            return;
        }
        super.setVisibility(visibility);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int[] processedMeasureWHSpec = this.panelLayoutHandler.processOnMeasure(widthMeasureSpec, heightMeasureSpec);
        super.onMeasure(processedMeasureWHSpec[0], processedMeasureWHSpec[1]);
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public boolean isKeyboardShowing() {
        return this.panelLayoutHandler.isKeyboardShowing();
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public boolean isVisible() {
        return this.panelLayoutHandler.isVisible();
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void handleShow() {
        super.setVisibility(0);
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void handleHide() {
        this.panelLayoutHandler.handleHide();
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void setIgnoreRecommendHeight(boolean isIgnoreRecommendHeight) {
        this.panelLayoutHandler.setIgnoreRecommendHeight(isIgnoreRecommendHeight);
    }

    @Override // cn.dreamtobe.kpswitch.IPanelHeightTarget
    public void refreshHeight(int panelHeight) {
        this.panelLayoutHandler.resetToRecommendPanelHeight(panelHeight);
    }

    @Override // cn.dreamtobe.kpswitch.IPanelHeightTarget
    public void onKeyboardShowing(boolean showing) {
        this.panelLayoutHandler.setIsKeyboardShowing(showing);
    }
}
