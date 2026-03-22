package com.jbzd.media.movecartoons.view.image;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.graphics.Xfermode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.NinePatchDrawable;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatImageView;
import com.jbzd.media.movecartoons.R$styleable;

/* loaded from: classes2.dex */
public class CircleImageView extends AppCompatImageView {
    private static final Xfermode MASK_XFERMODE = new PorterDuffXfermode(PorterDuff.Mode.DST_IN);
    private int mBorderColor;
    private int mBorderInsideColor;
    private int mBorderWidth;
    private Bitmap mask;
    private Paint paint;
    private boolean useDefaultStyle;

    public CircleImageView(Context context) {
        super(context);
        this.mBorderWidth = 2;
        this.mBorderColor = Color.parseColor("#f2f2f2");
        this.mBorderInsideColor = Color.parseColor("#f2f2f2");
        this.useDefaultStyle = false;
    }

    public static int dip2px(Context context, float f2) {
        return (int) ((f2 * context.getResources().getDisplayMetrics().density) + 0.5f);
    }

    private void drawBorder(Canvas canvas, int i2, int i3) {
        if (this.mBorderWidth == 0) {
            return;
        }
        Paint paint = new Paint();
        paint.setStyle(Paint.Style.STROKE);
        paint.setAntiAlias(true);
        this.mBorderWidth = 4;
        if (isSelected()) {
            this.mBorderWidth = 2;
            paint.setColor(Color.parseColor("#0fbf9a"));
        } else {
            paint.setColor(this.mBorderInsideColor);
        }
        paint.setStrokeWidth(this.mBorderWidth);
        canvas.drawCircle(i2 / 2, i3 / 2, (i2 - this.mBorderWidth) / 2, paint);
    }

    public static int px2dip(Context context, float f2) {
        return (int) ((f2 / context.getResources().getDisplayMetrics().density) + 0.5f);
    }

    private void useDefaultStyle(boolean z) {
        this.useDefaultStyle = z;
    }

    public Bitmap createOvalBitmap(int i2, int i3) {
        Bitmap createBitmap = Bitmap.createBitmap(i2, i3, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(createBitmap);
        Paint paint = new Paint();
        int i4 = this.mBorderWidth;
        int i5 = i4 + (-3) > 0 ? i4 - 3 : 1;
        if (i4 != 0) {
            i5 = 2;
        }
        float f2 = i5;
        canvas.drawOval(new RectF(f2, f2, i2 - i5, i3 - i5), paint);
        return createBitmap;
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDraw(Canvas canvas) {
        if (this.useDefaultStyle) {
            super.onDraw(canvas);
            return;
        }
        Drawable drawable = getDrawable();
        if (drawable == null || (drawable instanceof NinePatchDrawable)) {
            return;
        }
        if (this.paint == null) {
            Paint paint = new Paint();
            paint.setFilterBitmap(false);
            paint.setAntiAlias(true);
            paint.setXfermode(MASK_XFERMODE);
            this.paint = paint;
        }
        int width = getWidth();
        int height = getHeight();
        int saveLayer = canvas.saveLayer(0.0f, 0.0f, width, height, null, 31);
        drawable.setBounds(0, 0, width, height);
        drawable.draw(canvas);
        Bitmap bitmap = this.mask;
        if (bitmap == null || bitmap.isRecycled()) {
            this.mask = createOvalBitmap(width, height);
        }
        canvas.drawBitmap(this.mask, 0.0f, 0.0f, this.paint);
        canvas.restoreToCount(saveLayer);
        drawBorder(canvas, width, height);
    }

    public CircleImageView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public CircleImageView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mBorderWidth = 2;
        this.mBorderColor = Color.parseColor("#f2f2f2");
        this.mBorderInsideColor = Color.parseColor("#f2f2f2");
        this.useDefaultStyle = false;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.CircularImage);
        this.mBorderColor = obtainStyledAttributes.getColor(0, this.mBorderColor);
        this.mBorderInsideColor = obtainStyledAttributes.getColor(1, this.mBorderInsideColor);
        this.mBorderWidth = obtainStyledAttributes.getDimensionPixelOffset(2, (int) ((context.getResources().getDisplayMetrics().density * 2.0f) + 0.5f));
        obtainStyledAttributes.recycle();
    }
}
