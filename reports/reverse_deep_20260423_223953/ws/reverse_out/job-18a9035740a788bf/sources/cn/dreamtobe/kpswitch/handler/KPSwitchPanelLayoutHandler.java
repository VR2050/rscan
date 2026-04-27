package cn.dreamtobe.kpswitch.handler;

import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import cn.dreamtobe.kpswitch.IPanelConflictLayout;
import cn.dreamtobe.kpswitch.R;
import cn.dreamtobe.kpswitch.util.ViewUtil;

/* JADX INFO: loaded from: classes.dex */
public class KPSwitchPanelLayoutHandler implements IPanelConflictLayout {
    private boolean mIgnoreRecommendHeight;
    private final View panelLayout;
    private boolean mIsHide = false;
    private final int[] processedMeasureWHSpec = new int[2];
    private boolean mIsKeyboardShowing = false;

    public KPSwitchPanelLayoutHandler(View panelLayout, AttributeSet attrs) {
        this.mIgnoreRecommendHeight = false;
        this.panelLayout = panelLayout;
        if (attrs != null) {
            TypedArray typedArray = null;
            try {
                typedArray = panelLayout.getContext().obtainStyledAttributes(attrs, R.styleable.KPSwitchPanelLayout);
                this.mIgnoreRecommendHeight = typedArray.getBoolean(R.styleable.KPSwitchPanelLayout_ignore_recommend_height, false);
            } finally {
                if (typedArray != null) {
                    typedArray.recycle();
                }
            }
        }
    }

    public boolean filterSetVisibility(int visibility) {
        if (visibility == 0) {
            this.mIsHide = false;
        }
        if (visibility == this.panelLayout.getVisibility()) {
            return true;
        }
        return isKeyboardShowing() && visibility == 0;
    }

    public int[] processOnMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (this.mIsHide) {
            this.panelLayout.setVisibility(8);
            widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 1073741824);
            heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 1073741824);
        }
        int[] iArr = this.processedMeasureWHSpec;
        iArr[0] = widthMeasureSpec;
        iArr[1] = heightMeasureSpec;
        return iArr;
    }

    public void setIsKeyboardShowing(boolean isKeyboardShowing) {
        this.mIsKeyboardShowing = isKeyboardShowing;
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public boolean isKeyboardShowing() {
        return this.mIsKeyboardShowing;
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public boolean isVisible() {
        return !this.mIsHide;
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void handleShow() {
        throw new IllegalAccessError("You can't invoke handle show in handler, please instead of handling in the panel layout, maybe just need invoke super.setVisibility(View.VISIBLE)");
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void handleHide() {
        this.mIsHide = true;
    }

    public void resetToRecommendPanelHeight(int recommendPanelHeight) {
        if (this.mIgnoreRecommendHeight) {
            return;
        }
        ViewUtil.refreshHeight(this.panelLayout, recommendPanelHeight);
    }

    @Override // cn.dreamtobe.kpswitch.IPanelConflictLayout
    public void setIgnoreRecommendHeight(boolean ignoreRecommendHeight) {
        this.mIgnoreRecommendHeight = ignoreRecommendHeight;
    }
}
