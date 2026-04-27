package com.blankj.utilcode.util;

import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.material.snackbar.Snackbar;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
public final class SnackbarUtils {
    private static final int COLOR_DEFAULT = -16777217;
    private static final int COLOR_ERROR = -65536;
    private static final int COLOR_MESSAGE = -1;
    private static final int COLOR_SUCCESS = -13912576;
    private static final int COLOR_WARNING = -16128;
    public static final int LENGTH_INDEFINITE = -2;
    public static final int LENGTH_LONG = 0;
    public static final int LENGTH_SHORT = -1;
    private static WeakReference<Snackbar> sReference;
    private View.OnClickListener actionListener;
    private CharSequence actionText;
    private int actionTextColor;
    private int bgColor;
    private int bgResource;
    private int bottomMargin;
    private int duration;
    private CharSequence message;
    private int messageColor;
    private View view;

    @Retention(RetentionPolicy.SOURCE)
    public @interface Duration {
    }

    private SnackbarUtils(View parent) {
        setDefault();
        this.view = parent;
    }

    private void setDefault() {
        this.message = "";
        this.messageColor = COLOR_DEFAULT;
        this.bgColor = COLOR_DEFAULT;
        this.bgResource = -1;
        this.duration = -1;
        this.actionText = "";
        this.actionTextColor = COLOR_DEFAULT;
        this.bottomMargin = 0;
    }

    public static SnackbarUtils with(View view) {
        if (view == null) {
            throw new NullPointerException("Argument 'view' of type View (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return new SnackbarUtils(view);
    }

    public SnackbarUtils setMessage(CharSequence msg) {
        if (msg == null) {
            throw new NullPointerException("Argument 'msg' of type CharSequence (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        this.message = msg;
        return this;
    }

    public SnackbarUtils setMessageColor(int color) {
        this.messageColor = color;
        return this;
    }

    public SnackbarUtils setBgColor(int color) {
        this.bgColor = color;
        return this;
    }

    public SnackbarUtils setBgResource(int bgResource) {
        this.bgResource = bgResource;
        return this;
    }

    public SnackbarUtils setDuration(int duration) {
        this.duration = duration;
        return this;
    }

    public SnackbarUtils setAction(CharSequence text, View.OnClickListener listener) {
        if (text == null) {
            throw new NullPointerException("Argument 'text' of type CharSequence (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (listener == null) {
            throw new NullPointerException("Argument 'listener' of type View.OnClickListener (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return setAction(text, COLOR_DEFAULT, listener);
    }

    public SnackbarUtils setAction(CharSequence text, int color, View.OnClickListener listener) {
        if (text == null) {
            throw new NullPointerException("Argument 'text' of type CharSequence (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (listener == null) {
            throw new NullPointerException("Argument 'listener' of type View.OnClickListener (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        this.actionText = text;
        this.actionTextColor = color;
        this.actionListener = listener;
        return this;
    }

    public SnackbarUtils setBottomMargin(int bottomMargin) {
        this.bottomMargin = bottomMargin;
        return this;
    }

    public Snackbar show() {
        View view = this.view;
        if (view == null) {
            return null;
        }
        if (this.messageColor != COLOR_DEFAULT) {
            SpannableString spannableString = new SpannableString(this.message);
            ForegroundColorSpan colorSpan = new ForegroundColorSpan(this.messageColor);
            spannableString.setSpan(colorSpan, 0, spannableString.length(), 33);
            sReference = new WeakReference<>(Snackbar.make(view, spannableString, this.duration));
        } else {
            sReference = new WeakReference<>(Snackbar.make(view, this.message, this.duration));
        }
        Snackbar snackbar = sReference.get();
        View snackbarView = snackbar.getView();
        int i = this.bgResource;
        if (i != -1) {
            snackbarView.setBackgroundResource(i);
        } else {
            int i2 = this.bgColor;
            if (i2 != COLOR_DEFAULT) {
                snackbarView.setBackgroundColor(i2);
            }
        }
        if (this.bottomMargin != 0) {
            ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) snackbarView.getLayoutParams();
            params.bottomMargin = this.bottomMargin;
        }
        if (this.actionText.length() > 0 && this.actionListener != null) {
            int i3 = this.actionTextColor;
            if (i3 != COLOR_DEFAULT) {
                snackbar.setActionTextColor(i3);
            }
            snackbar.setAction(this.actionText, this.actionListener);
        }
        snackbar.show();
        return snackbar;
    }

    public void showSuccess() {
        this.bgColor = COLOR_SUCCESS;
        this.messageColor = -1;
        this.actionTextColor = -1;
        show();
    }

    public void showWarning() {
        this.bgColor = COLOR_WARNING;
        this.messageColor = -1;
        this.actionTextColor = -1;
        show();
    }

    public void showError() {
        this.bgColor = -65536;
        this.messageColor = -1;
        this.actionTextColor = -1;
        show();
    }

    public static void dismiss() {
        WeakReference<Snackbar> weakReference = sReference;
        if (weakReference != null && weakReference.get() != null) {
            sReference.get().dismiss();
            sReference = null;
        }
    }

    public static View getView() {
        Snackbar snackbar = sReference.get();
        if (snackbar == null) {
            return null;
        }
        return snackbar.getView();
    }

    public static void addView(int layoutId, ViewGroup.LayoutParams params) {
        if (params == null) {
            throw new NullPointerException("Argument 'params' of type ViewGroup.LayoutParams (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        View view = getView();
        if (view != null) {
            view.setPadding(0, 0, 0, 0);
            Snackbar.SnackbarLayout layout = (Snackbar.SnackbarLayout) view;
            View child = LayoutInflater.from(view.getContext()).inflate(layoutId, (ViewGroup) null);
            layout.addView(child, -1, params);
        }
    }

    public static void addView(View child, ViewGroup.LayoutParams params) {
        if (child == null) {
            throw new NullPointerException("Argument 'child' of type View (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (params == null) {
            throw new NullPointerException("Argument 'params' of type ViewGroup.LayoutParams (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        View view = getView();
        if (view != null) {
            view.setPadding(0, 0, 0, 0);
            Snackbar.SnackbarLayout layout = (Snackbar.SnackbarLayout) view;
            layout.addView(child, params);
        }
    }
}
