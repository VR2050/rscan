package com.ding.rtc;

import android.content.Context;
import android.graphics.Point;
import android.graphics.drawable.ColorDrawable;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.PopupWindow;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardTextPopup extends PopupWindow {
    private final Context mContext;
    private final EditText mEditText;
    private final Point mTextLocation;
    private final RtcWhiteboardTextObject mTextObject;

    public RtcWhiteboardTextPopup(final Context context, int x, int y, RtcWhiteboardTextObject textObject) {
        super(-2, -2);
        this.mTextLocation = new Point();
        this.mContext = context;
        this.mTextObject = textObject;
        float uiTextSize = textObject.format.size;
        DisplayMetrics metrics = context.getResources().getDisplayMetrics();
        uiTextSize = metrics.density > 0.0f ? uiTextSize / metrics.density : uiTextSize;
        EditText editText = new EditText(context);
        this.mEditText = editText;
        editText.setBackground(new ColorDrawable(0));
        this.mEditText.setHint("please enter text");
        this.mEditText.setTextColor(this.mTextObject.format.color);
        this.mEditText.setTextSize(uiTextSize);
        this.mEditText.setText(this.mTextObject.text);
        this.mEditText.setEms(10);
        this.mEditText.setFocusable(true);
        this.mEditText.setImeOptions(6);
        this.mEditText.setInputType(131073);
        this.mEditText.setPadding(0, 0, 0, 0);
        this.mEditText.setOnFocusChangeListener(new View.OnFocusChangeListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardTextPopup$wCXZneiNQZ6VPcrxQnnhb0GDvbk
            @Override // android.view.View.OnFocusChangeListener
            public final void onFocusChange(View view, boolean z) {
                this.f$0.lambda$new$1$RtcWhiteboardTextPopup(context, view, z);
            }
        });
        ViewTreeObserver vto = this.mEditText.getViewTreeObserver();
        vto.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.ding.rtc.RtcWhiteboardTextPopup.1
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                RtcWhiteboardTextPopup.this.mEditText.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                int[] loc = new int[2];
                RtcWhiteboardTextPopup.this.mEditText.getLocationOnScreen(loc);
                RtcWhiteboardTextPopup.this.mTextLocation.x = loc[0];
                RtcWhiteboardTextPopup.this.mTextLocation.y = loc[1];
            }
        });
        this.mEditText.requestFocus();
        setWidth(-2);
        setHeight(-2);
        setFocusable(true);
        setOutsideTouchable(true);
        setTouchable(true);
        setClippingEnabled(false);
        setBackgroundDrawable(new ColorDrawable(0));
        setSoftInputMode(20);
        setAnimationStyle(0);
        setContentView(this.mEditText);
    }

    public /* synthetic */ void lambda$new$1$RtcWhiteboardTextPopup(final Context context, View v, boolean hasFocus) {
        if (hasFocus) {
            this.mEditText.postDelayed(new Runnable() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardTextPopup$BHwyWzvOmwd_gvF_jNlEfdwKt_Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$RtcWhiteboardTextPopup(context);
                }
            }, 200L);
        }
    }

    public /* synthetic */ void lambda$null$0$RtcWhiteboardTextPopup(final Context context) {
        InputMethodManager imm = (InputMethodManager) context.getSystemService("input_method");
        if (imm != null) {
            imm.showSoftInput(this.mEditText, 1);
        }
    }

    @Override // android.widget.PopupWindow
    public void showAsDropDown(View anchor, int xoff, int yoff, int gravity) {
        super.showAsDropDown(anchor, xoff, yoff, gravity);
    }

    public RtcWhiteboardTextObject getTextObject() {
        RtcWhiteboardTextObject rtcWhiteboardTextObject;
        EditText editText = this.mEditText;
        if (editText != null && (rtcWhiteboardTextObject = this.mTextObject) != null) {
            rtcWhiteboardTextObject.setText(editText.getText().toString());
            int w = this.mEditText.getWidth();
            int h = this.mEditText.getHeight();
            int y = this.mTextLocation.y;
            this.mTextObject.setRect(this.mTextLocation.x, y, w, h);
        }
        return this.mTextObject;
    }
}
