package im.uwrkaxlmjj.ui.hviews.helper;

import android.view.View;
import java.lang.ref.WeakReference;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryAlphaViewHelper {
    private float mDisabledAlpha;
    private float mPressedAlpha;
    private WeakReference<View> mTarget;
    private boolean mChangeAlphaWhenPress = true;
    private boolean mChangeAlphaWhenDisable = true;
    private float mNormalAlpha = 1.0f;

    public MryAlphaViewHelper(View target) {
        this.mPressedAlpha = 0.5f;
        this.mDisabledAlpha = 0.5f;
        this.mTarget = new WeakReference<>(target);
        this.mPressedAlpha = MryResHelper.getAttrFloatValue(target.getContext(), R.style.mryAlphaPressed);
        this.mDisabledAlpha = MryResHelper.getAttrFloatValue(target.getContext(), R.style.mryAlphaDisabled);
    }

    public MryAlphaViewHelper(View target, float pressedAlpha, float disabledAlpha) {
        this.mPressedAlpha = 0.5f;
        this.mDisabledAlpha = 0.5f;
        this.mTarget = new WeakReference<>(target);
        this.mPressedAlpha = pressedAlpha;
        this.mDisabledAlpha = disabledAlpha;
    }

    public void onPressedChanged(View current, boolean pressed) {
        View target = this.mTarget.get();
        if (target == null) {
            return;
        }
        if (current.isEnabled()) {
            target.setAlpha((this.mChangeAlphaWhenPress && pressed && current.isClickable()) ? this.mPressedAlpha : this.mNormalAlpha);
        } else if (this.mChangeAlphaWhenDisable) {
            target.setAlpha(this.mDisabledAlpha);
        }
    }

    public void onEnabledChanged(View current, boolean enabled) {
        View target = this.mTarget.get();
        if (target == null) {
            return;
        }
        float alphaForIsEnable = (!this.mChangeAlphaWhenDisable || enabled) ? this.mNormalAlpha : this.mDisabledAlpha;
        if (current != target && target.isEnabled() != enabled) {
            target.setEnabled(enabled);
        }
        target.setAlpha(alphaForIsEnable);
    }

    public void setChangeAlphaWhenPress(boolean changeAlphaWhenPress) {
        this.mChangeAlphaWhenPress = changeAlphaWhenPress;
    }

    public void setChangeAlphaWhenDisable(boolean changeAlphaWhenDisable) {
        this.mChangeAlphaWhenDisable = changeAlphaWhenDisable;
        View target = this.mTarget.get();
        if (target != null) {
            onEnabledChanged(target, target.isEnabled());
        }
    }
}
