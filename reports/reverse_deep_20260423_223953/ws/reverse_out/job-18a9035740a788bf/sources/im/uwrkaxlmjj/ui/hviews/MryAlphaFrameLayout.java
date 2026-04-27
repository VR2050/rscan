package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.ui.hviews.helper.MryAlphaViewHelper;

/* JADX INFO: loaded from: classes5.dex */
public class MryAlphaFrameLayout extends FrameLayout implements MryAlphaViewInf {
    private MryAlphaViewHelper mAlphaViewHelper;

    public MryAlphaFrameLayout(Context context) {
        super(context);
    }

    public MryAlphaFrameLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public MryAlphaFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    private MryAlphaViewHelper getAlphaViewHelper() {
        if (this.mAlphaViewHelper == null) {
            this.mAlphaViewHelper = new MryAlphaViewHelper(this);
        }
        return this.mAlphaViewHelper;
    }

    @Override // android.view.View
    public void setPressed(boolean pressed) {
        super.setPressed(pressed);
        getAlphaViewHelper().onPressedChanged(this, pressed);
    }

    @Override // android.view.View
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        getAlphaViewHelper().onEnabledChanged(this, enabled);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.MryAlphaViewInf
    public void setChangeAlphaWhenPress(boolean changeAlphaWhenPress) {
        getAlphaViewHelper().setChangeAlphaWhenPress(changeAlphaWhenPress);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.MryAlphaViewInf
    public void setChangeAlphaWhenDisable(boolean changeAlphaWhenDisable) {
        getAlphaViewHelper().setChangeAlphaWhenDisable(changeAlphaWhenDisable);
    }
}
