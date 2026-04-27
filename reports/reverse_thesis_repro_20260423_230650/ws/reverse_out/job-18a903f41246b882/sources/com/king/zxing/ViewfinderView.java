package com.king.zxing;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.View;
import androidx.core.content.ContextCompat;
import com.google.zxing.ResultPoint;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public final class ViewfinderView extends View {
    private static final int CURRENT_POINT_OPACITY = 160;
    private static final int MAX_RESULT_POINTS = 20;
    private static final int POINT_SIZE = 20;
    private int cornerColor;
    private int cornerRectHeight;
    private int cornerRectWidth;
    private Rect frame;
    private int frameColor;
    private int frameHeight;
    private int frameLineWidth;
    private float frameRatio;
    private int frameWidth;
    private int gridColumn;
    private int gridHeight;
    private boolean isShowResultPoint;
    private String labelText;
    private int labelTextColor;
    private TextLocation labelTextLocation;
    private float labelTextPadding;
    private float labelTextSize;
    private int laserColor;
    private LaserStyle laserStyle;
    private List<ResultPoint> lastPossibleResultPoints;
    private int maskColor;
    private Paint paint;
    private List<ResultPoint> possibleResultPoints;
    private int resultPointColor;
    private int scannerAnimationDelay;
    public int scannerEnd;
    private int scannerLineHeight;
    private int scannerLineMoveDistance;
    public int scannerStart;
    private int screenHeight;
    private int screenWidth;
    private TextPaint textPaint;

    public enum LaserStyle {
        NONE(0),
        LINE(1),
        GRID(2);

        private int mValue;

        LaserStyle(int value) {
            this.mValue = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static LaserStyle getFromInt(int value) {
            for (LaserStyle style : values()) {
                if (style.mValue == value) {
                    return style;
                }
            }
            return LINE;
        }
    }

    public enum TextLocation {
        TOP(0),
        BOTTOM(1);

        private int mValue;

        TextLocation(int value) {
            this.mValue = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static TextLocation getFromInt(int value) {
            for (TextLocation location : values()) {
                if (location.mValue == value) {
                    return location;
                }
            }
            return TOP;
        }
    }

    public ViewfinderView(Context context) {
        this(context, null);
    }

    public ViewfinderView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public ViewfinderView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.scannerStart = 0;
        this.scannerEnd = 0;
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        TypedArray array = context.obtainStyledAttributes(attrs, R.styleable.ViewfinderView);
        this.maskColor = array.getColor(R.styleable.ViewfinderView_maskColor, ContextCompat.getColor(context, R.color.viewfinder_mask));
        this.frameColor = array.getColor(R.styleable.ViewfinderView_frameColor, ContextCompat.getColor(context, R.color.viewfinder_frame));
        this.cornerColor = array.getColor(R.styleable.ViewfinderView_cornerColor, ContextCompat.getColor(context, R.color.viewfinder_corner));
        this.laserColor = array.getColor(R.styleable.ViewfinderView_laserColor, ContextCompat.getColor(context, R.color.viewfinder_laser));
        this.resultPointColor = array.getColor(R.styleable.ViewfinderView_resultPointColor, ContextCompat.getColor(context, R.color.viewfinder_result_point_color));
        this.labelText = array.getString(R.styleable.ViewfinderView_labelText);
        this.labelTextColor = array.getColor(R.styleable.ViewfinderView_labelTextColor, ContextCompat.getColor(context, R.color.viewfinder_text_color));
        this.labelTextSize = array.getDimension(R.styleable.ViewfinderView_labelTextSize, TypedValue.applyDimension(2, 14.0f, getResources().getDisplayMetrics()));
        this.labelTextPadding = array.getDimension(R.styleable.ViewfinderView_labelTextPadding, TypedValue.applyDimension(1, 24.0f, getResources().getDisplayMetrics()));
        this.labelTextLocation = TextLocation.getFromInt(array.getInt(R.styleable.ViewfinderView_labelTextLocation, 0));
        this.isShowResultPoint = array.getBoolean(R.styleable.ViewfinderView_showResultPoint, false);
        this.frameWidth = array.getDimensionPixelSize(R.styleable.ViewfinderView_frameWidth, 0);
        this.frameHeight = array.getDimensionPixelSize(R.styleable.ViewfinderView_frameHeight, 0);
        this.laserStyle = LaserStyle.getFromInt(array.getInt(R.styleable.ViewfinderView_laserStyle, LaserStyle.LINE.mValue));
        this.gridColumn = array.getInt(R.styleable.ViewfinderView_gridColumn, 20);
        this.gridHeight = (int) array.getDimension(R.styleable.ViewfinderView_gridHeight, TypedValue.applyDimension(1, 40.0f, getResources().getDisplayMetrics()));
        this.cornerRectWidth = (int) array.getDimension(R.styleable.ViewfinderView_cornerRectWidth, TypedValue.applyDimension(1, 4.0f, getResources().getDisplayMetrics()));
        this.cornerRectHeight = (int) array.getDimension(R.styleable.ViewfinderView_cornerRectHeight, TypedValue.applyDimension(1, 16.0f, getResources().getDisplayMetrics()));
        this.scannerLineMoveDistance = (int) array.getDimension(R.styleable.ViewfinderView_scannerLineMoveDistance, TypedValue.applyDimension(1, 2.0f, getResources().getDisplayMetrics()));
        this.scannerLineHeight = (int) array.getDimension(R.styleable.ViewfinderView_scannerLineHeight, TypedValue.applyDimension(1, 5.0f, getResources().getDisplayMetrics()));
        this.frameLineWidth = (int) array.getDimension(R.styleable.ViewfinderView_frameLineWidth, TypedValue.applyDimension(1, 1.0f, getResources().getDisplayMetrics()));
        this.scannerAnimationDelay = array.getInteger(R.styleable.ViewfinderView_scannerAnimationDelay, 15);
        this.frameRatio = array.getFloat(R.styleable.ViewfinderView_frameRatio, 0.625f);
        array.recycle();
        this.paint = new Paint(1);
        this.textPaint = new TextPaint(1);
        this.possibleResultPoints = new ArrayList(5);
        this.lastPossibleResultPoints = null;
        this.screenWidth = getDisplayMetrics().widthPixels;
        this.screenHeight = getDisplayMetrics().heightPixels;
        int size = (int) (Math.min(this.screenWidth, r1) * this.frameRatio);
        int i = this.frameWidth;
        if (i <= 0 || i > this.screenWidth) {
            this.frameWidth = size;
        }
        int i2 = this.frameHeight;
        if (i2 <= 0 || i2 > this.screenHeight) {
            this.frameHeight = size;
        }
    }

    private DisplayMetrics getDisplayMetrics() {
        return getResources().getDisplayMetrics();
    }

    public void setLabelText(String labelText) {
        this.labelText = labelText;
    }

    public void setLabelTextColor(int color) {
        this.labelTextColor = color;
    }

    public void setLabelTextColorResource(int id) {
        this.labelTextColor = ContextCompat.getColor(getContext(), id);
    }

    public void setLabelTextSize(float textSize) {
        this.labelTextSize = textSize;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int leftOffset = (((this.screenWidth - this.frameWidth) / 2) + getPaddingLeft()) - getPaddingRight();
        int topOffset = (((this.screenHeight - this.frameHeight) / 2) + getPaddingTop()) - getPaddingBottom();
        this.frame = new Rect(leftOffset, topOffset, this.frameWidth + leftOffset, this.frameHeight + topOffset);
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        if (this.frame == null) {
            return;
        }
        if (this.scannerStart == 0 || this.scannerEnd == 0) {
            this.scannerStart = this.frame.top;
            this.scannerEnd = this.frame.bottom - this.scannerLineHeight;
        }
        int width = canvas.getWidth();
        int height = canvas.getHeight();
        drawExterior(canvas, this.frame, width, height);
        drawLaserScanner(canvas, this.frame);
        drawFrame(canvas, this.frame);
        drawCorner(canvas, this.frame);
        drawTextInfo(canvas, this.frame);
        drawResultPoint(canvas, this.frame);
        postInvalidateDelayed(this.scannerAnimationDelay, this.frame.left - 20, this.frame.top - 20, this.frame.right + 20, this.frame.bottom + 20);
    }

    private void drawTextInfo(Canvas canvas, Rect frame) {
        if (!TextUtils.isEmpty(this.labelText)) {
            this.textPaint.setColor(this.labelTextColor);
            this.textPaint.setTextSize(this.labelTextSize);
            this.textPaint.setTextAlign(Paint.Align.CENTER);
            StaticLayout staticLayout = new StaticLayout(this.labelText, this.textPaint, canvas.getWidth(), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, true);
            if (this.labelTextLocation == TextLocation.BOTTOM) {
                canvas.translate(frame.left + (frame.width() / 2), frame.bottom + this.labelTextPadding);
                staticLayout.draw(canvas);
            } else {
                canvas.translate(frame.left + (frame.width() / 2), (frame.top - this.labelTextPadding) - staticLayout.getHeight());
                staticLayout.draw(canvas);
            }
        }
    }

    private void drawCorner(Canvas canvas, Rect frame) {
        this.paint.setColor(this.cornerColor);
        canvas.drawRect(frame.left, frame.top, frame.left + this.cornerRectWidth, frame.top + this.cornerRectHeight, this.paint);
        canvas.drawRect(frame.left, frame.top, frame.left + this.cornerRectHeight, frame.top + this.cornerRectWidth, this.paint);
        canvas.drawRect(frame.right - this.cornerRectWidth, frame.top, frame.right, frame.top + this.cornerRectHeight, this.paint);
        canvas.drawRect(frame.right - this.cornerRectHeight, frame.top, frame.right, frame.top + this.cornerRectWidth, this.paint);
        canvas.drawRect(frame.left, frame.bottom - this.cornerRectWidth, frame.left + this.cornerRectHeight, frame.bottom, this.paint);
        canvas.drawRect(frame.left, frame.bottom - this.cornerRectHeight, frame.left + this.cornerRectWidth, frame.bottom, this.paint);
        canvas.drawRect(frame.right - this.cornerRectWidth, frame.bottom - this.cornerRectHeight, frame.right, frame.bottom, this.paint);
        canvas.drawRect(frame.right - this.cornerRectHeight, frame.bottom - this.cornerRectWidth, frame.right, frame.bottom, this.paint);
    }

    private void drawLaserScanner(Canvas canvas, Rect frame) {
        if (this.laserStyle != null) {
            this.paint.setColor(this.laserColor);
            int i = AnonymousClass1.$SwitchMap$com$king$zxing$ViewfinderView$LaserStyle[this.laserStyle.ordinal()];
            if (i == 1) {
                drawLineScanner(canvas, frame);
            } else if (i == 2) {
                drawGridScanner(canvas, frame);
            }
            this.paint.setShader(null);
        }
    }

    /* JADX INFO: renamed from: com.king.zxing.ViewfinderView$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$king$zxing$ViewfinderView$LaserStyle;

        static {
            int[] iArr = new int[LaserStyle.values().length];
            $SwitchMap$com$king$zxing$ViewfinderView$LaserStyle = iArr;
            try {
                iArr[LaserStyle.LINE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$king$zxing$ViewfinderView$LaserStyle[LaserStyle.GRID.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    private void drawLineScanner(Canvas canvas, Rect frame) {
        LinearGradient linearGradient = new LinearGradient(frame.left, this.scannerStart, frame.left, this.scannerStart + this.scannerLineHeight, shadeColor(this.laserColor), this.laserColor, Shader.TileMode.MIRROR);
        this.paint.setShader(linearGradient);
        if (this.scannerStart <= this.scannerEnd) {
            float f = frame.left + (this.scannerLineHeight * 2);
            float f2 = this.scannerStart;
            int i = frame.right;
            int i2 = this.scannerLineHeight;
            RectF rectF = new RectF(f, f2, i - (i2 * 2), this.scannerStart + i2);
            canvas.drawOval(rectF, this.paint);
            this.scannerStart += this.scannerLineMoveDistance;
            return;
        }
        this.scannerStart = frame.top;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void drawGridScanner(android.graphics.Canvas r17, android.graphics.Rect r18) {
        /*
            Method dump skipped, instruction units count: 228
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.king.zxing.ViewfinderView.drawGridScanner(android.graphics.Canvas, android.graphics.Rect):void");
    }

    public int shadeColor(int color) {
        String hax = Integer.toHexString(color);
        String result = "01" + hax.substring(2);
        return Integer.valueOf(result, 16).intValue();
    }

    private void drawFrame(Canvas canvas, Rect frame) {
        this.paint.setColor(this.frameColor);
        canvas.drawRect(frame.left, frame.top, frame.right, frame.top + this.frameLineWidth, this.paint);
        canvas.drawRect(frame.left, frame.top, frame.left + this.frameLineWidth, frame.bottom, this.paint);
        canvas.drawRect(frame.right - this.frameLineWidth, frame.top, frame.right, frame.bottom, this.paint);
        canvas.drawRect(frame.left, frame.bottom - this.frameLineWidth, frame.right, frame.bottom, this.paint);
    }

    private void drawExterior(Canvas canvas, Rect frame, int width, int height) {
        this.paint.setColor(this.maskColor);
        canvas.drawRect(0.0f, 0.0f, width, frame.top, this.paint);
        canvas.drawRect(0.0f, frame.top, frame.left, frame.bottom, this.paint);
        canvas.drawRect(frame.right, frame.top, width, frame.bottom, this.paint);
        canvas.drawRect(0.0f, frame.bottom, width, height, this.paint);
    }

    private void drawResultPoint(Canvas canvas, Rect frame) {
        if (!this.isShowResultPoint) {
            return;
        }
        List<ResultPoint> currentPossible = this.possibleResultPoints;
        List<ResultPoint> currentLast = this.lastPossibleResultPoints;
        if (currentPossible.isEmpty()) {
            this.lastPossibleResultPoints = null;
        } else {
            this.possibleResultPoints = new ArrayList(5);
            this.lastPossibleResultPoints = currentPossible;
            this.paint.setAlpha(CURRENT_POINT_OPACITY);
            this.paint.setColor(this.resultPointColor);
            synchronized (currentPossible) {
                for (ResultPoint point : currentPossible) {
                    canvas.drawCircle(point.getX(), point.getY(), 10.0f, this.paint);
                }
            }
        }
        if (currentLast != null) {
            this.paint.setAlpha(80);
            this.paint.setColor(this.resultPointColor);
            synchronized (currentLast) {
                for (ResultPoint point2 : currentLast) {
                    canvas.drawCircle(point2.getX(), point2.getY(), 10.0f, this.paint);
                }
            }
        }
    }

    public void drawViewfinder() {
        invalidate();
    }

    public boolean isShowResultPoint() {
        return this.isShowResultPoint;
    }

    public void setLaserStyle(LaserStyle laserStyle) {
        this.laserStyle = laserStyle;
    }

    public void setShowResultPoint(boolean showResultPoint) {
        this.isShowResultPoint = showResultPoint;
    }

    public void addPossibleResultPoint(ResultPoint point) {
        if (this.isShowResultPoint) {
            List<ResultPoint> points = this.possibleResultPoints;
            synchronized (points) {
                points.add(point);
                int size = points.size();
                if (size > 20) {
                    points.subList(0, size - 10).clear();
                }
            }
        }
    }
}
