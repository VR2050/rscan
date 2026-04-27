package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.ui.hviews.helper.MryAlphaViewHelper;

/* JADX INFO: loaded from: classes5.dex */
public class MryAlphaLinearLayout extends LinearLayout implements MryAlphaViewInf {
    private MryAlphaViewHelper mAlphaViewHelper;

    public MryAlphaLinearLayout(Context context) {
        super(context);
    }

    public MryAlphaLinearLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public MryAlphaLinearLayout(Context context, AttributeSet attrs, int defStyleAttr) {
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
