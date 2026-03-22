package com.qunidayede.supportlibrary.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.annotation.DrawableRes;
import com.google.android.material.textfield.TextInputEditText;
import com.qunidayede.supportlibrary.R$drawable;
import com.qunidayede.supportlibrary.R$styleable;

/* loaded from: classes2.dex */
public class ClearEditText extends TextInputEditText {

    /* renamed from: c */
    public static final int f10341c = R$drawable.ic_clear_default_normal;

    /* renamed from: e */
    public Drawable f10342e;

    /* renamed from: com.qunidayede.supportlibrary.widget.ClearEditText$a */
    public class C4054a implements TextWatcher {
        public C4054a() {
        }

        @Override // android.text.TextWatcher
        public void afterTextChanged(Editable editable) {
            ClearEditText.this.m4577a();
        }

        @Override // android.text.TextWatcher
        public void beforeTextChanged(CharSequence charSequence, int i2, int i3, int i4) {
        }

        @Override // android.text.TextWatcher
        public void onTextChanged(CharSequence charSequence, int i2, int i3, int i4) {
        }
    }

    public ClearEditText(Context context) {
        super(context);
        init(context, null);
    }

    /* renamed from: a */
    public void m4577a() {
        Drawable[] compoundDrawables = getCompoundDrawables();
        if (length() > 0) {
            setCompoundDrawablesWithIntrinsicBounds(compoundDrawables[0], compoundDrawables[1], this.f10342e, compoundDrawables[3]);
        } else {
            setCompoundDrawablesWithIntrinsicBounds(compoundDrawables[0], compoundDrawables[1], (Drawable) null, compoundDrawables[3]);
        }
    }

    public final void init(Context context, AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ClearEditText);
        Drawable drawable = getResources().getDrawable(obtainStyledAttributes.getResourceId(R$styleable.ClearEditText_iconClear, f10341c));
        this.f10342e = drawable;
        this.f10342e = new BitmapDrawable(getResources(), Bitmap.createScaledBitmap(((BitmapDrawable) drawable).getBitmap(), 20, 20, true));
        m4577a();
        obtainStyledAttributes.recycle();
        addTextChangedListener(new C4054a());
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int x;
        if (motionEvent.getAction() == 0 && (x = (int) motionEvent.getX()) >= getWidth() - getCompoundPaddingRight() && x < getWidth()) {
            setText("");
        }
        return super.onTouchEvent(motionEvent);
    }

    public void setIconClear(@DrawableRes int i2) {
        this.f10342e = getResources().getDrawable(i2);
        m4577a();
    }

    public ClearEditText(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        init(context, attributeSet);
    }

    public ClearEditText(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        init(context, attributeSet);
    }
}
