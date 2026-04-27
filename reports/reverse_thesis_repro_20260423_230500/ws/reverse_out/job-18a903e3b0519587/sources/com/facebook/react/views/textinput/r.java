package com.facebook.react.views.textinput;

import android.text.SpannableStringBuilder;
import android.widget.EditText;

/* JADX INFO: loaded from: classes.dex */
public final class r {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final SpannableStringBuilder f8275a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f8276b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f8277c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f8278d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f8279e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final int f8280f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final CharSequence f8281g;

    public r(EditText editText) {
        this.f8275a = new SpannableStringBuilder(editText.getText());
        this.f8276b = editText.getTextSize();
        this.f8279e = editText.getInputType();
        this.f8281g = editText.getHint();
        this.f8277c = editText.getMinLines();
        this.f8278d = editText.getMaxLines();
        this.f8280f = editText.getBreakStrategy();
    }

    public void a(EditText editText) {
        editText.setText(this.f8275a);
        editText.setTextSize(0, this.f8276b);
        editText.setMinLines(this.f8277c);
        editText.setMaxLines(this.f8278d);
        editText.setInputType(this.f8279e);
        editText.setHint(this.f8281g);
        editText.setBreakStrategy(this.f8280f);
    }
}
