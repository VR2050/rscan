package im.uwrkaxlmjj.ui.hui.adapter.pageAdapter;

import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import java.util.WeakHashMap;

/* JADX INFO: loaded from: classes5.dex */
public class PageHolder<H extends PageHolder> extends RecyclerView.ViewHolder {
    private WeakHashMap<Object, View> mViewMap;

    public PageHolder(View itemView) {
        this(itemView, Theme.key_windowBackgroundWhite);
    }

    public PageHolder(View itemView, String backgroundThemeKey) {
        this(itemView, backgroundThemeKey == null ? 0 : Theme.getColor(backgroundThemeKey));
    }

    public PageHolder(View itemView, int backgroundColor) {
        super(itemView);
        if (backgroundColor != 0) {
            itemView.setBackgroundColor(backgroundColor);
        }
    }

    private WeakHashMap<Object, View> getViewMap() {
        if (this.mViewMap == null) {
            this.mViewMap = new WeakHashMap<>();
        }
        return this.mViewMap;
    }

    public <V extends View> V getView(int i) {
        View viewFindViewById = getViewMap().get(Integer.valueOf(i));
        if (viewFindViewById == null) {
            viewFindViewById = this.itemView.findViewById(i);
            getViewMap().put(Integer.valueOf(i), viewFindViewById);
        }
        if (viewFindViewById != null) {
            return (V) viewFindViewById;
        }
        return null;
    }

    public H setText(int i, int i2) {
        return (H) setText(i, LocaleController.getString(i2 + "", i2));
    }

    public H setText(View view, int i) {
        return (H) setText(view, LocaleController.getString(i + "", i));
    }

    public H setText(int i, CharSequence charSequence) {
        return (H) setText(getView(i), charSequence);
    }

    public H setText(View textView, CharSequence text) {
        if (text != null) {
            if (!"null".equals(((Object) text) + "") && (textView instanceof TextView)) {
                ((TextView) textView).setText(text);
            }
        }
        return this;
    }

    public H setHint(int i, int i2) {
        return (H) setHint(i, LocaleController.getString(i2 + "", i2));
    }

    public H setHint(View view, int i) {
        return (H) setHint(view, LocaleController.getString(i + "", i));
    }

    public H setHint(int i, CharSequence charSequence) {
        return (H) setHint(getView(i), charSequence);
    }

    public H setHint(View textView, CharSequence text) {
        if (text != null) {
            if (!"null".equals(((Object) text) + "") && (textView instanceof TextView)) {
                ((TextView) textView).setHint(text);
            }
        }
        return this;
    }

    public H setTextColorThemeGray(int i) {
        return (H) setTextColorThemeGray(getView(i));
    }

    public H setTextColorThemeGray(View view) {
        return (H) setTextColor(view, Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
    }

    public H setTextColorThemeBlack(int i) {
        return (H) setTextColorThemeBlack(getView(i));
    }

    public H setTextColorThemeBlack(View view) {
        return (H) setTextColor(view, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
    }

    public H setTextColorThemeHint(int i) {
        return (H) setTextColorThemeHint(getView(i));
    }

    public H setTextColorThemeHint(View view) {
        return (H) setTextColor(view, Theme.getColor(Theme.key_dialogTextHint));
    }

    public H setTextColorThemePrimary(int i) {
        return (H) setTextColorThemePrimary(getView(i));
    }

    public H setTextColorThemePrimary(View view) {
        return (H) setTextColor(view, Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
    }

    public H setTextColorThemeLink(int i) {
        return (H) setTextColorThemeLink(getView(i));
    }

    public H setTextColorThemeLink(View view) {
        return (H) setTextColor(view, Theme.getColor(Theme.key_windowBackgroundWhiteLinkText));
    }

    public H setTextColor(int i, String str) {
        return (H) setTextColor(i, Theme.getColor(str));
    }

    public H setTextColor(View view, String str) {
        return (H) setTextColor(view, Theme.getColor(str));
    }

    public H setTextColor(int i, int i2) {
        return (H) setTextColor(getView(i), i2);
    }

    public H setTextColor(View textView, int color) {
        if (textView instanceof TextView) {
            ((TextView) textView).setTextColor(color);
        }
        return this;
    }

    public H setTextSize(int i, int i2) {
        return (H) setTextSize(i, 2, i2);
    }

    public H setTextSize(View view, int i) {
        return (H) setTextSize(view, 2, i);
    }

    public H setTextSize(int i, int i2, int i3) {
        return (H) setTextSize(getView(i), i2, i3);
    }

    public H setTextSize(View textView, int unit, int textSize) {
        if (textView instanceof TextView) {
            ((TextView) textView).setTextSize(unit, textSize);
        }
        return this;
    }

    public H setTextBold(int i) {
        return (H) setTextBold(getView(i));
    }

    public H setTextBold(View view) {
        return (H) setTextTypeface(view, AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
    }

    public H setTextItalic(int i) {
        return (H) setTextItalic(getView(i));
    }

    public H setTextItalic(View view) {
        return (H) setTextTypeface(view, AndroidUtilities.getTypeface("fonts/ritalic.ttf"));
    }

    public H setTextTypeface(int i, Typeface typeface) {
        return (H) setTextTypeface(getView(i), typeface, -1);
    }

    public H setTextTypeface(View view, Typeface typeface) {
        return (H) setTextTypeface(view, typeface, -1);
    }

    public H setTextTypeface(int i, Typeface typeface, int i2) {
        return (H) setTextTypeface(getView(i), typeface, i2);
    }

    public H setTextTypeface(View textView, Typeface typeface, int typefaceStyle) {
        if (textView instanceof TextView) {
            if (typefaceStyle != -1) {
                ((TextView) textView).setTypeface(typeface, typefaceStyle);
            } else {
                ((TextView) textView).setTypeface(typeface);
            }
        }
        return this;
    }

    public H setImageColorFilter(int i, String str) {
        return (H) setImageColorFilter(getView(i), str);
    }

    public H setImageColorFilter(View view, String str) {
        return (H) setImageColorFilter(view, str, PorterDuff.Mode.MULTIPLY);
    }

    public H setImageColorFilter(int i, int i2) {
        return (H) setImageColorFilter(getView(i), i2);
    }

    public H setImageColorFilter(View view, int i) {
        return (H) setImageColorFilter(view, i, PorterDuff.Mode.MULTIPLY);
    }

    public H setImageColorFilter(int i, int i2, PorterDuff.Mode mode) {
        return (H) setImageColorFilter(getView(i), i2, mode);
    }

    public H setImageColorFilter(int i, String str, PorterDuff.Mode mode) {
        return (H) setImageColorFilter(getView(i), str, mode);
    }

    public H setImageColorFilter(View view, String str, PorterDuff.Mode mode) {
        return (H) setImageColorFilter(view, Theme.getColor(str), mode);
    }

    public H setImageColorFilter(View imageView, int color, PorterDuff.Mode mode) {
        if (imageView instanceof ImageView) {
            ((ImageView) imageView).setColorFilter(color, mode);
        }
        return this;
    }

    public H setImageResId(int i, int i2) {
        return (H) setImageResId(getView(i), i2);
    }

    public H setImageResId(View imageView, int imageResId) {
        if (imageView instanceof ImageView) {
            ((ImageView) imageView).setImageResource(imageResId);
        }
        return this;
    }

    public H setImageDrawable(int i, Drawable drawable) {
        return (H) setImageDrawable(getView(i), drawable);
    }

    public H setImageDrawable(View imageView, Drawable iamgeDrawable) {
        if (iamgeDrawable != null && (imageView instanceof ImageView)) {
            ((ImageView) imageView).setImageDrawable(iamgeDrawable);
        }
        return this;
    }

    public H setGone(int i, boolean z) {
        return (H) setGone(getView(i), z);
    }

    public H setGone(View view, boolean gone) {
        if (view != null) {
            if (gone && view.getVisibility() != 8) {
                view.setVisibility(8);
            } else if (!gone && view.getVisibility() != 0) {
                view.setVisibility(0);
            }
        }
        return this;
    }

    public H setInVisible(int i, boolean z) {
        return (H) setInVisible(getView(i), z);
    }

    public H setInVisible(View view, boolean inVisible) {
        if (view != null) {
            if (inVisible && view.getVisibility() != 4) {
                view.setVisibility(4);
            } else if (!inVisible && (view.getVisibility() != 0 || view.getVisibility() != 8)) {
                view.setVisibility(0);
            }
        }
        return this;
    }

    public H setBackgroundPrimaryColor(int i) {
        return (H) setBackgroundPrimaryColor(getView(i));
    }

    public H setBackgroundPrimaryColor(View view) {
        return (H) setBackgroundColor(view, Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
    }

    public H setBackgroundWindowColor(int i) {
        return (H) setBackgroundWindowColor(getView(i));
    }

    public H setBackgroundWindowColor(View view) {
        return (H) setBackgroundColor(view, Theme.getColor(Theme.key_windowBackgroundWhite));
    }

    public H setBackgroundWindowGrayColor(int i) {
        return (H) setBackgroundWindowGrayColor(getView(i));
    }

    public H setBackgroundWindowGrayColor(View view) {
        return (H) setBackgroundColor(view, Theme.getColor(Theme.key_windowBackgroundGray));
    }

    public H setBackgroundColor(int i, String str) {
        return (H) setBackgroundColor(i, Theme.getColor(str));
    }

    public H setBackgroundColor(int i, int i2) {
        return (H) setBackgroundColor(getView(i), i2);
    }

    public H setBackgroundColor(View view, String str) {
        return (H) setBackgroundColor(view, Theme.getColor(str));
    }

    public H setBackgroundColor(View view, int colorResId) {
        if (view != null) {
            view.setBackgroundColor(colorResId);
        }
        return this;
    }

    public H setBackgroundDrawable(int i, Drawable drawable) {
        return (H) setBackgroundDrawable(getView(i), drawable);
    }

    public H setBackgroundDrawable(View view, Drawable background) {
        if (view != null) {
            view.setBackground(background);
        }
        return this;
    }

    public H setOnClickListener(int i, View.OnClickListener onClickListener) {
        return (H) setOnClickListener(getView(i), onClickListener);
    }

    public H setOnClickListener(View view, View.OnClickListener onClickListener) {
        if (view != null) {
            view.setOnClickListener(onClickListener);
        }
        return this;
    }
}
