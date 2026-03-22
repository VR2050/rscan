package com.lljjcoder.style.citylist.sortlistview;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;
import androidx.exifinterface.media.ExifInterface;
import com.lljjcoder.style.citypickerview.C3949R;

/* loaded from: classes2.dex */
public class SideBar extends View {

    /* renamed from: b */
    public static String[] f10200b = {ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "B", "C", "D", ExifInterface.LONGITUDE_EAST, "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", ExifInterface.LATITUDE_SOUTH, ExifInterface.GPS_DIRECTION_TRUE, "U", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, ExifInterface.LONGITUDE_WEST, "X", "Y", "Z", "#"};
    private int choose;
    private TextView mTextDialog;
    private OnTouchingLetterChangedListener onTouchingLetterChangedListener;
    private Paint paint;

    public interface OnTouchingLetterChangedListener {
        void onTouchingLetterChanged(String str);
    }

    public SideBar(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.choose = -1;
        this.paint = new Paint();
    }

    @Override // android.view.View
    public boolean dispatchTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        float y = motionEvent.getY();
        int i2 = this.choose;
        OnTouchingLetterChangedListener onTouchingLetterChangedListener = this.onTouchingLetterChangedListener;
        int height = (int) ((y / getHeight()) * f10200b.length);
        if (action != 1) {
            setBackgroundResource(C3949R.drawable.sidebar_background);
            if (i2 != height && height >= 0) {
                String[] strArr = f10200b;
                if (height < strArr.length) {
                    if (onTouchingLetterChangedListener != null) {
                        onTouchingLetterChangedListener.onTouchingLetterChanged(strArr[height]);
                    }
                    TextView textView = this.mTextDialog;
                    if (textView != null) {
                        textView.setText(f10200b[height]);
                        this.mTextDialog.setVisibility(0);
                    }
                    this.choose = height;
                    invalidate();
                }
            }
        } else {
            setBackgroundDrawable(new ColorDrawable(0));
            this.choose = -1;
            invalidate();
            TextView textView2 = this.mTextDialog;
            if (textView2 != null) {
                textView2.setVisibility(4);
            }
        }
        return true;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int height = getHeight();
        int width = getWidth();
        int length = height / f10200b.length;
        for (int i2 = 0; i2 < f10200b.length; i2++) {
            this.paint.setColor(Color.rgb(33, 65, 98));
            this.paint.setTypeface(Typeface.DEFAULT_BOLD);
            this.paint.setAntiAlias(true);
            this.paint.setTextSize(20.0f);
            if (i2 == this.choose) {
                this.paint.setColor(Color.parseColor("#000000"));
                this.paint.setFakeBoldText(true);
            }
            canvas.drawText(f10200b[i2], (width / 2) - (this.paint.measureText(f10200b[i2]) / 2.0f), (length * i2) + length, this.paint);
            this.paint.reset();
        }
    }

    public void setOnTouchingLetterChangedListener(OnTouchingLetterChangedListener onTouchingLetterChangedListener) {
        this.onTouchingLetterChangedListener = onTouchingLetterChangedListener;
    }

    public void setTextView(TextView textView) {
        this.mTextDialog = textView;
    }

    public SideBar(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.choose = -1;
        this.paint = new Paint();
    }

    public SideBar(Context context) {
        super(context);
        this.choose = -1;
        this.paint = new Paint();
    }
}
