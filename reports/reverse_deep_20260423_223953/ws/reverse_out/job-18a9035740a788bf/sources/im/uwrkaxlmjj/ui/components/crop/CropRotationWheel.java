package im.uwrkaxlmjj.ui.components.crop;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CropRotationWheel extends FrameLayout {
    private static final int DELTA_ANGLE = 5;
    private static final int MAX_ANGLE = 45;
    private ImageView aspectRatioButton;
    private Paint bluePaint;
    private TextView degreesLabel;
    private float prevX;
    protected float rotation;
    private RotationWheelListener rotationListener;
    private RectF tempRect;
    private Paint whitePaint;

    public interface RotationWheelListener {
        void aspectRatioPressed();

        void onChange(float f);

        void onEnd(float f);

        void onStart();

        void rotate90Pressed();
    }

    public CropRotationWheel(Context context) {
        super(context);
        this.tempRect = new RectF(0.0f, 0.0f, 0.0f, 0.0f);
        Paint paint = new Paint();
        this.whitePaint = paint;
        paint.setStyle(Paint.Style.FILL);
        this.whitePaint.setColor(-1);
        this.whitePaint.setAlpha(255);
        this.whitePaint.setAntiAlias(true);
        Paint paint2 = new Paint();
        this.bluePaint = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.bluePaint.setColor(-11420173);
        this.bluePaint.setAlpha(255);
        this.bluePaint.setAntiAlias(true);
        ImageView imageView = new ImageView(context);
        this.aspectRatioButton = imageView;
        imageView.setImageResource(R.drawable.tool_cropfix);
        this.aspectRatioButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.aspectRatioButton.setScaleType(ImageView.ScaleType.CENTER);
        this.aspectRatioButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropRotationWheel$EsVxO0DpxRd7Iz0Gks5x-hxO310
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$0$CropRotationWheel(view);
            }
        });
        this.aspectRatioButton.setContentDescription(LocaleController.getString("AccDescrAspectRatio", R.string.AccDescrAspectRatio));
        addView(this.aspectRatioButton, LayoutHelper.createFrame(70, 64, 19));
        ImageView rotation90Button = new ImageView(context);
        rotation90Button.setImageResource(R.drawable.tool_rotate);
        rotation90Button.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        rotation90Button.setScaleType(ImageView.ScaleType.CENTER);
        rotation90Button.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropRotationWheel$xD-bKIvDnya2IfFQC_x4kUYbyE0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$CropRotationWheel(view);
            }
        });
        rotation90Button.setContentDescription(LocaleController.getString("AccDescrRotate", R.string.AccDescrRotate));
        addView(rotation90Button, LayoutHelper.createFrame(70, 64, 21));
        TextView textView = new TextView(context);
        this.degreesLabel = textView;
        textView.setTextColor(-1);
        addView(this.degreesLabel, LayoutHelper.createFrame(-2, -2, 49));
        setWillNotDraw(false);
        setRotation(0.0f, false);
    }

    public /* synthetic */ void lambda$new$0$CropRotationWheel(View v) {
        RotationWheelListener rotationWheelListener = this.rotationListener;
        if (rotationWheelListener != null) {
            rotationWheelListener.aspectRatioPressed();
        }
    }

    public /* synthetic */ void lambda$new$1$CropRotationWheel(View v) {
        RotationWheelListener rotationWheelListener = this.rotationListener;
        if (rotationWheelListener != null) {
            rotationWheelListener.rotate90Pressed();
        }
    }

    public void setFreeform(boolean freeform) {
        this.aspectRatioButton.setVisibility(freeform ? 0 : 8);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(Math.min(width, AndroidUtilities.dp(400.0f)), 1073741824), heightMeasureSpec);
    }

    public void reset() {
        setRotation(0.0f, false);
    }

    public void setListener(RotationWheelListener listener) {
        this.rotationListener = listener;
    }

    public void setRotation(float rotation, boolean animated) {
        this.rotation = rotation;
        float value = this.rotation;
        if (Math.abs(value) < 0.099d) {
            value = Math.abs(value);
        }
        this.degreesLabel.setText(String.format("%.1fº", Float.valueOf(value)));
        invalidate();
    }

    public void setAspectLock(boolean enabled) {
        this.aspectRatioButton.setColorFilter(enabled ? new PorterDuffColorFilter(-11420173, PorterDuff.Mode.MULTIPLY) : null);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent ev) {
        int action = ev.getActionMasked();
        float x = ev.getX();
        if (action != 0) {
            if (action == 1 || action == 3) {
                RotationWheelListener rotationWheelListener = this.rotationListener;
                if (rotationWheelListener != null) {
                    rotationWheelListener.onEnd(this.rotation);
                }
                AndroidUtilities.makeAccessibilityAnnouncement(String.format("%.1f°", Float.valueOf(this.rotation)));
            } else if (action == 2) {
                float delta = this.prevX - x;
                float newAngle = Math.max(-45.0f, Math.min(45.0f, this.rotation + ((float) ((((double) (delta / AndroidUtilities.density)) / 3.141592653589793d) / 1.649999976158142d))));
                if (Math.abs(newAngle - this.rotation) > 0.001d) {
                    if (Math.abs(newAngle) < 0.05d) {
                        newAngle = 0.0f;
                    }
                    setRotation(newAngle, false);
                    RotationWheelListener rotationWheelListener2 = this.rotationListener;
                    if (rotationWheelListener2 != null) {
                        rotationWheelListener2.onChange(this.rotation);
                    }
                    this.prevX = x;
                }
            }
        } else {
            this.prevX = x;
            RotationWheelListener rotationWheelListener3 = this.rotationListener;
            if (rotationWheelListener3 != null) {
                rotationWheelListener3.onStart();
            }
        }
        return true;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        Paint paint;
        super.onDraw(canvas);
        int width = getWidth();
        int height = getHeight();
        float angle = (-this.rotation) * 2.0f;
        float delta = angle % 5.0f;
        int segments = (int) Math.floor(angle / 5.0f);
        for (int i = 0; i < 16; i++) {
            Paint paint2 = this.whitePaint;
            int a = i;
            if (a < segments || (a == 0 && delta < 0.0f)) {
                Paint paint3 = this.bluePaint;
                paint = paint3;
            } else {
                paint = paint2;
            }
            drawLine(canvas, a, delta, width, height, a == segments || (a == 0 && segments == -1), paint);
            if (i != 0) {
                int a2 = -i;
                Paint paint4 = a2 > segments ? this.bluePaint : this.whitePaint;
                drawLine(canvas, a2, delta, width, height, a2 == segments + 1, paint4);
            }
        }
        this.bluePaint.setAlpha(255);
        this.tempRect.left = (width - AndroidUtilities.dp(2.5f)) / 2;
        this.tempRect.top = (height - AndroidUtilities.dp(22.0f)) / 2;
        this.tempRect.right = (AndroidUtilities.dp(2.5f) + width) / 2;
        this.tempRect.bottom = (AndroidUtilities.dp(22.0f) + height) / 2;
        canvas.drawRoundRect(this.tempRect, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), this.bluePaint);
    }

    protected void drawLine(Canvas canvas, int i, float delta, int width, int height, boolean center, Paint paint) {
        int radius = (int) ((width / 2.0f) - AndroidUtilities.dp(70.0f));
        float angle = 90.0f - ((i * 5) + delta);
        int val = (int) (((double) radius) * Math.cos(Math.toRadians(angle)));
        int x = (width / 2) + val;
        float f = Math.abs(val) / radius;
        int alpha = Math.min(255, Math.max(0, (int) ((1.0f - (f * f)) * 255.0f)));
        Paint paint2 = center ? this.bluePaint : paint;
        paint2.setAlpha(alpha);
        int w = center ? 4 : 2;
        int h = AndroidUtilities.dp(center ? 16.0f : 12.0f);
        canvas.drawRect(x - (w / 2), (height - h) / 2, (w / 2) + x, (height + h) / 2, paint2);
    }
}
