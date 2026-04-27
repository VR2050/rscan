package im.uwrkaxlmjj.ui.hviews.sidebar;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.View;
import android.widget.TextView;
import androidx.exifinterface.media.ExifInterface;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SideBar extends View {
    public static String[] a = {ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "B", "C", "D", ExifInterface.LONGITUDE_EAST, "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", ExifInterface.LATITUDE_SOUTH, ExifInterface.GPS_DIRECTION_TRUE, "U", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, ExifInterface.LONGITUDE_WEST, "X", "Y", "Z", "#"};
    public static String[] b = {"↑", "☆", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "B", "C", "D", ExifInterface.LONGITUDE_EAST, "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", ExifInterface.LATITUDE_SOUTH, ExifInterface.GPS_DIRECTION_TRUE, "U", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, ExifInterface.LONGITUDE_WEST, "X", "Y", "Z", "#"};
    private Paint bitmapPaint;
    public String[] chars;
    private int choose;
    private int height;
    private Context mContext;
    private TextView mTextDialog;
    private OnTouchingLetterChangedListener onTouchingLetterChangedListener;
    private boolean onlyChar;
    private Paint textPaint;

    public interface OnTouchingLetterChangedListener {
        void onTouchingLetterChanged(String str);
    }

    public void setTextView(TextView mTextDialog) {
        this.mTextDialog = mTextDialog;
    }

    public SideBar(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.choose = -1;
        this.textPaint = new Paint();
        this.bitmapPaint = new Paint();
        this.onlyChar = true;
        this.mContext = context;
        this.chars = a;
    }

    public SideBar(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SideBar(Context context) {
        this(context, null);
    }

    public void setOnlyChar(boolean flag) {
        this.onlyChar = flag;
        if (flag) {
            this.chars = a;
        } else {
            this.chars = b;
        }
        requestLayout();
        invalidate();
    }

    public void setCharsOnly() {
        this.chars = a;
    }

    public void setTextColor(int color) {
        this.textPaint.setColor(color);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int defaultCharHeight = AndroidUtilities.dp(15.0f);
        int width = AndroidUtilities.dp(35.0f);
        int height = Math.min(this.chars.length * defaultCharHeight, AndroidUtilities.dp(500.0f));
        setMeasuredDimension(width, height);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int width = getWidth();
        int height = getHeight();
        this.height = height;
        int singleHeight = height / this.chars.length;
        Bitmap bitmap = BitmapFactory.decodeResource(getResources(), R.id.ic_slide_bar_char_bg);
        for (int i = 0; i < this.chars.length; i++) {
            this.textPaint.setColor(Theme.getColor(Theme.key_sidebar_textDefaultColor));
            this.textPaint.setTypeface(Typeface.DEFAULT);
            this.textPaint.setAntiAlias(true);
            this.textPaint.setTextSize(dip2px(this.mContext, 9.5f));
            this.textPaint.setTextAlign(Paint.Align.CENTER);
            if (i == this.choose) {
                this.textPaint.setColor(-1);
                this.textPaint.setFakeBoldText(true);
                this.bitmapPaint.setAlpha(225);
            } else {
                this.bitmapPaint.setAlpha(0);
            }
            canvas.drawBitmap(bitmap, ((width / 2) - (bitmap.getWidth() / 2)) - AndroidUtilities.dp(1.0f), ((singleHeight - bitmap.getHeight()) / 2) + (singleHeight * i), this.bitmapPaint);
            Paint.FontMetrics fontMetrics = this.textPaint.getFontMetrics();
            float distance = ((fontMetrics.bottom - fontMetrics.top) / 2.0f) - fontMetrics.bottom;
            float baseline = (singleHeight / 2) + distance + (singleHeight * i);
            canvas.drawText(this.chars[i], width / 2, baseline, this.textPaint);
            this.textPaint.reset();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0057  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean dispatchTouchEvent(android.view.MotionEvent r9) {
        /*
            r8 = this;
            int r0 = r9.getAction()
            float r1 = r9.getY()
            int r2 = r8.choose
            im.uwrkaxlmjj.ui.hviews.sidebar.SideBar$OnTouchingLetterChangedListener r3 = r8.onTouchingLetterChangedListener
            int r4 = r8.height
            float r4 = (float) r4
            float r4 = r1 / r4
            java.lang.String[] r5 = r8.chars
            int r6 = r5.length
            float r6 = (float) r6
            float r4 = r4 * r6
            int r4 = (int) r4
            r6 = 1
            if (r0 == r6) goto L40
            if (r2 == r4) goto L65
            if (r4 < 0) goto L65
            int r7 = r5.length
            if (r4 >= r7) goto L65
            if (r3 == 0) goto L29
            r5 = r5[r4]
            r3.onTouchingLetterChanged(r5)
        L29:
            android.widget.TextView r5 = r8.mTextDialog
            if (r5 == 0) goto L3a
            java.lang.String[] r7 = r8.chars
            r7 = r7[r4]
            r5.setText(r7)
            android.widget.TextView r5 = r8.mTextDialog
            r7 = 0
            r5.setVisibility(r7)
        L3a:
            r8.choose = r4
            r8.invalidate()
            goto L65
        L40:
            if (r4 >= 0) goto L46
            boolean r5 = r8.onlyChar
            if (r5 == 0) goto L57
        L46:
            if (r4 <= 0) goto L5a
            java.lang.String[] r5 = r8.chars
            int r7 = r5.length
            if (r4 >= r7) goto L5a
            r5 = r5[r4]
            java.lang.String r7 = "↑"
            boolean r5 = r5.equals(r7)
            if (r5 == 0) goto L5a
        L57:
            r5 = -1
            r8.choose = r5
        L5a:
            r8.invalidate()
            android.widget.TextView r5 = r8.mTextDialog
            if (r5 == 0) goto L65
            r7 = 4
            r5.setVisibility(r7)
        L65:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.dispatchTouchEvent(android.view.MotionEvent):boolean");
    }

    public void setOnTouchingLetterChangedListener(OnTouchingLetterChangedListener onTouchingLetterChangedListener) {
        this.onTouchingLetterChangedListener = onTouchingLetterChangedListener;
    }

    public static int dip2px(Context context, float dpValue) {
        float scale = context.getResources().getDisplayMetrics().density;
        return (int) ((dpValue * scale) + 0.5f);
    }

    public void setChars(String[] chars) {
        if (chars.length != 0) {
            if (this.onlyChar) {
                this.chars = chars;
                this.choose = 0;
            } else {
                String[] newChars = new String[chars.length + 2];
                newChars[0] = "↑";
                newChars[1] = "☆";
                for (int i = 0; i < chars.length; i++) {
                    newChars[i + 2] = chars[i];
                }
                this.chars = newChars;
                this.choose = 2;
            }
            requestLayout();
            invalidate();
        }
    }

    public void setChooseChar(String c) {
        int i = 0;
        while (true) {
            String[] strArr = this.chars;
            if (i < strArr.length) {
                if (strArr[i].equals(c)) {
                    this.choose = i;
                    invalidate();
                }
                i++;
            } else {
                return;
            }
        }
    }
}
