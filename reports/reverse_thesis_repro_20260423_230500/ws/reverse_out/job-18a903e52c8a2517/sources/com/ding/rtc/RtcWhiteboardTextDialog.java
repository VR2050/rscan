package com.ding.rtc;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Point;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardTextDialog extends Dialog {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private static int DY = -1;
    private static final int MAGIC = 81;
    private final Context mContext;
    private EditText mEditText;
    private boolean mIsEditText;
    private final int mPositionX;
    private final int mPositionY;
    private final Point mTextLocation;
    private final RtcWhiteboardTextObject mTextObject;

    public RtcWhiteboardTextDialog(Context context, int x, int y, RtcWhiteboardTextObject textObject) {
        super(context);
        this.mTextLocation = new Point();
        this.mIsEditText = false;
        this.mContext = context;
        this.mPositionX = x;
        this.mPositionY = y;
        this.mTextObject = textObject;
        this.mIsEditText = textObject.getText() != null;
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final Window dialogWindow = getWindow();
        float uiTextSize = this.mTextObject.format.size;
        DisplayMetrics metrics = this.mContext.getResources().getDisplayMetrics();
        if (metrics.density > 0.0f) {
            uiTextSize /= metrics.density;
        }
        EditText editText = new EditText(this.mContext);
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
        this.mEditText.setPadding(0, 0, 0, 80);
        ViewTreeObserver vto = this.mEditText.getViewTreeObserver();
        vto.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.ding.rtc.RtcWhiteboardTextDialog.1
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                RtcWhiteboardTextDialog.this.mEditText.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                int[] loc = new int[2];
                RtcWhiteboardTextDialog.this.mEditText.getLocationOnScreen(loc);
                RtcWhiteboardTextDialog.this.mTextLocation.x = loc[0];
                RtcWhiteboardTextDialog.this.mTextLocation.y = loc[1];
                WindowManager.LayoutParams wlp = dialogWindow.getAttributes();
                if (RtcWhiteboardTextDialog.DY == -1) {
                    int unused = RtcWhiteboardTextDialog.DY = RtcWhiteboardTextDialog.this.mTextLocation.y - wlp.y;
                }
            }
        });
        this.mEditText.requestFocus();
        requestWindowFeature(1);
        dialogWindow.setBackgroundDrawable(new ColorDrawable(0));
        setContentView(this.mEditText);
        dialogWindow.setSoftInputMode(20);
        dialogWindow.clearFlags(2);
        WindowManager.LayoutParams wlp = dialogWindow.getAttributes();
        wlp.gravity = 8388659;
        wlp.x = this.mPositionX;
        int i = DY;
        if (i != -1) {
            wlp.y = this.mPositionY - i;
        } else {
            wlp.y = this.mPositionY - 81;
        }
        wlp.width = -2;
        wlp.height = -2;
        dialogWindow.setAttributes(wlp);
        setCanceledOnTouchOutside(true);
    }

    public RtcWhiteboardTextObject getTextObject() {
        RtcWhiteboardTextObject rtcWhiteboardTextObject;
        EditText editText = this.mEditText;
        if (editText != null && (rtcWhiteboardTextObject = this.mTextObject) != null) {
            rtcWhiteboardTextObject.setText(editText.getText().toString());
            int x = this.mIsEditText ? this.mPositionX : this.mTextLocation.x;
            int y = this.mIsEditText ? this.mPositionY : this.mTextLocation.y;
            int w = this.mEditText.getWidth();
            int h = this.mEditText.getHeight();
            this.mTextObject.setRect(x, y, w, h);
        }
        return this.mTextObject;
    }
}
