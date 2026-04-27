package im.uwrkaxlmjj.ui.components.paint.views;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.paint.Swatch;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ColorPicker extends FrameLayout {
    private static final int[] COLORS = {-1431751, -2409774, -13610525, -11942419, -8337308, -205211, -223667, -16777216, -1};
    private static final float[] LOCATIONS = {0.0f, 0.14f, 0.24f, 0.39f, 0.49f, 0.62f, 0.73f, 0.85f, 1.0f};
    private Paint backgroundPaint;
    private boolean changingWeight;
    private ColorPickerDelegate delegate;
    private boolean dragging;
    private float draggingFactor;
    private Paint gradientPaint;
    private boolean interacting;
    private OvershootInterpolator interpolator;
    private float location;
    private RectF rectF;
    private ImageView settingsButton;
    private Drawable shadowDrawable;
    private Paint swatchPaint;
    private Paint swatchStrokePaint;
    private ImageView undoButton;
    private boolean wasChangingWeight;
    private float weight;

    public interface ColorPickerDelegate {
        void onBeganColorPicking();

        void onColorValueChanged();

        void onFinishedColorPicking();

        void onSettingsPressed();

        void onUndoPressed();
    }

    public ColorPicker(Context context) {
        super(context);
        this.interpolator = new OvershootInterpolator(1.02f);
        this.gradientPaint = new Paint(1);
        this.backgroundPaint = new Paint(1);
        this.swatchPaint = new Paint(1);
        this.swatchStrokePaint = new Paint(1);
        this.rectF = new RectF();
        this.location = 1.0f;
        this.weight = 0.27f;
        setWillNotDraw(false);
        this.shadowDrawable = getResources().getDrawable(R.drawable.knob_shadow);
        this.backgroundPaint.setColor(-1);
        this.swatchStrokePaint.setStyle(Paint.Style.STROKE);
        this.swatchStrokePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        ImageView imageView = new ImageView(context);
        this.settingsButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.settingsButton.setImageResource(R.drawable.photo_paint_brush);
        addView(this.settingsButton, LayoutHelper.createFrame(60, 52.0f));
        this.settingsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (ColorPicker.this.delegate != null) {
                    ColorPicker.this.delegate.onSettingsPressed();
                }
            }
        });
        ImageView imageView2 = new ImageView(context);
        this.undoButton = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.undoButton.setImageResource(R.drawable.photo_undo);
        addView(this.undoButton, LayoutHelper.createFrame(60, 52.0f));
        this.undoButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (ColorPicker.this.delegate != null) {
                    ColorPicker.this.delegate.onUndoPressed();
                }
            }
        });
        float f = context.getSharedPreferences("paint", 0).getFloat("last_color_location", 1.0f);
        this.location = f;
        setLocation(f);
    }

    public void setUndoEnabled(boolean enabled) {
        this.undoButton.setAlpha(enabled ? 1.0f : 0.3f);
        this.undoButton.setEnabled(enabled);
    }

    public void setDelegate(ColorPickerDelegate colorPickerDelegate) {
        this.delegate = colorPickerDelegate;
    }

    public View getSettingsButton() {
        return this.settingsButton;
    }

    public void setSettingsButtonImage(int resId) {
        this.settingsButton.setImageResource(resId);
    }

    public Swatch getSwatch() {
        return new Swatch(colorForLocation(this.location), this.location, this.weight);
    }

    public void setSwatch(Swatch swatch) {
        setLocation(swatch.colorLocation);
        setWeight(swatch.brushWeight);
    }

    public int colorForLocation(float location) {
        if (location <= 0.0f) {
            return COLORS[0];
        }
        if (location >= 1.0f) {
            return COLORS[r0.length - 1];
        }
        int leftIndex = -1;
        int rightIndex = -1;
        int i = 1;
        while (true) {
            float[] fArr = LOCATIONS;
            if (i >= fArr.length) {
                break;
            }
            float value = fArr[i];
            if (value <= location) {
                i++;
            } else {
                leftIndex = i - 1;
                rightIndex = i;
                break;
            }
        }
        float[] fArr2 = LOCATIONS;
        float leftLocation = fArr2[leftIndex];
        int[] iArr = COLORS;
        int leftColor = iArr[leftIndex];
        float rightLocation = fArr2[rightIndex];
        int rightColor = iArr[rightIndex];
        float factor = (location - leftLocation) / (rightLocation - leftLocation);
        return interpolateColors(leftColor, rightColor, factor);
    }

    private int interpolateColors(int leftColor, int rightColor, float factor) {
        float factor2 = Math.min(Math.max(factor, 0.0f), 1.0f);
        int r1 = Color.red(leftColor);
        int r2 = Color.red(rightColor);
        int g1 = Color.green(leftColor);
        int g2 = Color.green(rightColor);
        int b1 = Color.blue(leftColor);
        int b2 = Color.blue(rightColor);
        int r = Math.min(255, (int) (r1 + ((r2 - r1) * factor2)));
        int g = Math.min(255, (int) (g1 + ((g2 - g1) * factor2)));
        int b = Math.min(255, (int) (b1 + ((b2 - b1) * factor2)));
        return Color.argb(255, r, g, b);
    }

    public void setLocation(float value) {
        this.location = value;
        int color = colorForLocation(value);
        this.swatchPaint.setColor(color);
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        if (hsv[0] < 0.001d && hsv[1] < 0.001d && hsv[2] > 0.92f) {
            int c = (int) ((1.0f - (((hsv[2] - 0.92f) / 0.08f) * 0.22f)) * 255.0f);
            this.swatchStrokePaint.setColor(Color.rgb(c, c, c));
        } else {
            this.swatchStrokePaint.setColor(color);
        }
        invalidate();
    }

    public void setWeight(float value) {
        this.weight = value;
        invalidate();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        ColorPickerDelegate colorPickerDelegate;
        if (event.getPointerCount() > 1) {
            return false;
        }
        float x = event.getX() - this.rectF.left;
        float y = event.getY() - this.rectF.top;
        if (!this.interacting && y < (-AndroidUtilities.dp(10.0f))) {
            return false;
        }
        int action = event.getActionMasked();
        if (action == 3 || action == 1 || action == 6) {
            if (this.interacting && (colorPickerDelegate = this.delegate) != null) {
                colorPickerDelegate.onFinishedColorPicking();
                getContext().getSharedPreferences("paint", 0).edit().putFloat("last_color_location", this.location).commit();
            }
            this.interacting = false;
            this.wasChangingWeight = this.changingWeight;
            this.changingWeight = false;
            setDragging(false, true);
        } else if (action == 0 || action == 2) {
            if (!this.interacting) {
                this.interacting = true;
                ColorPickerDelegate colorPickerDelegate2 = this.delegate;
                if (colorPickerDelegate2 != null) {
                    colorPickerDelegate2.onBeganColorPicking();
                }
            }
            float colorLocation = Math.max(0.0f, Math.min(1.0f, x / this.rectF.width()));
            setLocation(colorLocation);
            setDragging(true, true);
            if (y < (-AndroidUtilities.dp(10.0f))) {
                this.changingWeight = true;
                float weightLocation = ((-y) - AndroidUtilities.dp(10.0f)) / AndroidUtilities.dp(190.0f);
                setWeight(Math.max(0.0f, Math.min(1.0f, weightLocation)));
            }
            ColorPickerDelegate colorPickerDelegate3 = this.delegate;
            if (colorPickerDelegate3 != null) {
                colorPickerDelegate3.onColorValueChanged();
            }
            return true;
        }
        return false;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int width = right - left;
        int height = bottom - top;
        this.gradientPaint.setShader(new LinearGradient(AndroidUtilities.dp(56.0f), 0.0f, width - AndroidUtilities.dp(56.0f), 0.0f, COLORS, LOCATIONS, Shader.TileMode.REPEAT));
        int y = height - AndroidUtilities.dp(32.0f);
        this.rectF.set(AndroidUtilities.dp(56.0f), y, width - AndroidUtilities.dp(56.0f), AndroidUtilities.dp(12.0f) + y);
        ImageView imageView = this.settingsButton;
        imageView.layout(width - imageView.getMeasuredWidth(), height - AndroidUtilities.dp(52.0f), width, height);
        this.undoButton.layout(0, height - AndroidUtilities.dp(52.0f), this.settingsButton.getMeasuredWidth(), height);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        canvas.drawRoundRect(this.rectF, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), this.gradientPaint);
        int cx = (int) (this.rectF.left + (this.rectF.width() * this.location));
        int cy = (int) ((this.rectF.centerY() + (this.draggingFactor * (-AndroidUtilities.dp(70.0f)))) - (this.changingWeight ? this.weight * AndroidUtilities.dp(190.0f) : 0.0f));
        int side = (int) (AndroidUtilities.dp(24.0f) * (this.draggingFactor + 1.0f) * 0.5f);
        this.shadowDrawable.setBounds(cx - side, cy - side, cx + side, cy + side);
        this.shadowDrawable.draw(canvas);
        float swatchRadius = (((int) Math.floor(AndroidUtilities.dp(4.0f) + ((AndroidUtilities.dp(19.0f) - AndroidUtilities.dp(4.0f)) * this.weight))) * (this.draggingFactor + 1.0f)) / 2.0f;
        canvas.drawCircle(cx, cy, (AndroidUtilities.dp(22.0f) / 2) * (this.draggingFactor + 1.0f), this.backgroundPaint);
        canvas.drawCircle(cx, cy, swatchRadius, this.swatchPaint);
        canvas.drawCircle(cx, cy, swatchRadius - AndroidUtilities.dp(0.5f), this.swatchStrokePaint);
    }

    private void setDraggingFactor(float factor) {
        this.draggingFactor = factor;
        invalidate();
    }

    public float getDraggingFactor() {
        return this.draggingFactor;
    }

    private void setDragging(boolean value, boolean animated) {
        if (this.dragging == value) {
            return;
        }
        this.dragging = value;
        float target = value ? 1.0f : 0.0f;
        if (animated) {
            Animator a = ObjectAnimator.ofFloat(this, "draggingFactor", this.draggingFactor, target);
            a.setInterpolator(this.interpolator);
            int duration = 300;
            if (this.wasChangingWeight) {
                duration = (int) (300 + (this.weight * 75.0f));
            }
            a.setDuration(duration);
            a.start();
            return;
        }
        setDraggingFactor(target);
    }
}
