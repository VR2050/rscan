package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.core.graphics.drawable.DrawableCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class MryCheckBox extends AppCompatCheckBox {
    private PorterDuff.Mode mBackgroundTintMode;
    private int[] mColorThemeArr;

    public MryCheckBox(Context context) {
        this(context, null);
    }

    public MryCheckBox(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MryCheckBox(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    protected void init(Context context) {
        this.mColorThemeArr = new int[]{Theme.getColor(Theme.key_themeCheckBoxUnchecked), 0};
        this.mColorThemeArr[1] = Theme.getColor(Theme.key_themeCheckBoxChecked);
        changeState();
    }

    protected void changeState() {
        if (this.mColorThemeArr == null) {
            return;
        }
        if (!isChecked()) {
            ColorStateList colorStateList = ColorStateList.valueOf(this.mColorThemeArr[0]);
            if (Build.VERSION.SDK_INT >= 21) {
                setBackgroundTintList(colorStateList);
            } else {
                setSuopportBackgroundTintList(colorStateList, this.mBackgroundTintMode);
            }
            setButtonTintList(colorStateList);
            return;
        }
        ColorStateList colorStateList2 = ColorStateList.valueOf(this.mColorThemeArr[1]);
        if (Build.VERSION.SDK_INT >= 21) {
            setBackgroundTintList(colorStateList2);
        } else {
            setSuopportBackgroundTintList(colorStateList2, this.mBackgroundTintMode);
        }
        setButtonTintList(colorStateList2);
    }

    @Override // android.widget.CompoundButton, android.widget.Checkable
    public void setChecked(boolean checked) {
        super.setChecked(checked);
        changeState();
    }

    @Override // android.widget.CompoundButton
    public void setButtonTintMode(PorterDuff.Mode tintMode) {
        super.setButtonTintMode(tintMode);
    }

    @Override // android.widget.CompoundButton
    public void setButtonTintList(ColorStateList tint) {
        super.setButtonTintList(tint);
    }

    @Override // android.view.View
    public void setBackgroundTintList(ColorStateList tint) {
        super.setBackgroundTintList(tint);
    }

    @Override // android.view.View
    public void setBackgroundTintMode(PorterDuff.Mode tintMode) {
        super.setBackgroundTintMode(tintMode);
        this.mBackgroundTintMode = tintMode;
    }

    protected void setSuopportBackgroundTintList(ColorStateList colorStateList, PorterDuff.Mode tintMode) {
        Drawable backgroundDrawable = getBackground();
        if (backgroundDrawable != null) {
            try {
                Drawable backgroundDrawable2 = DrawableCompat.wrap(backgroundDrawable).mutate();
                DrawableCompat.setTintList(backgroundDrawable2, colorStateList);
                DrawableCompat.setTintMode(backgroundDrawable2, tintMode);
                if (backgroundDrawable2.isStateful()) {
                    backgroundDrawable2.setState(getDrawableState());
                }
                setBackground(backgroundDrawable2);
            } catch (Exception e) {
                FileLog.e(getClass().getName() + " =====> setSuopportBackgroundTintList() = " + e.getMessage());
            }
        }
    }

    public void setColorThemeArr(int[] colorThemeArr) {
        this.mColorThemeArr = colorThemeArr;
        changeState();
    }

    public void setCheckedColor(String themeCheckColorKey) {
        setCheckedColor(Theme.getColor(themeCheckColorKey));
    }

    public void setCheckedColor(int checkedColor) {
        this.mColorThemeArr[1] = checkedColor;
        changeState();
    }

    public void setUncheckedColor(String themeUncheckedColorKey) {
        setUncheckedColor(Theme.getColor(themeUncheckedColorKey));
    }

    public void setUncheckedColor(int uncheckedColor) {
        this.mColorThemeArr[0] = uncheckedColor;
        changeState();
    }

    public void setMryText(int resId) {
        setText(LocaleController.getString(resId));
    }

    public void setMryHint(int resId) {
        setHint(LocaleController.getString(resId));
    }

    public void setTextColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setTextColor(Theme.getColor(colorThemeKey));
    }

    public void setHintColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setHintTextColor(Theme.getColor(colorThemeKey));
    }

    public void setBackgroundColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setBackgroundColor(Theme.getColor(colorThemeKey));
    }

    public void setHighlightColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setHighlightColor(Theme.getColor(colorThemeKey));
    }

    public void setBold() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
    }

    public void setItalic() {
        setTypeface(AndroidUtilities.getTypeface("fonts/ritalic.ttf"));
    }

    public void setBoldAndItalic() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf"));
    }

    public void setMono() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmono.ttf"));
    }
}
