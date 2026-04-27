package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ComposeShader;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.view.ViewCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ColorPicker extends FrameLayout {
    private int centerX;
    private int centerY;
    private Drawable circleDrawable;
    private Paint circlePaint;
    private boolean circlePressed;
    private EditTextBoldCursor[] colorEditText;
    private LinearGradient colorGradient;
    private float[] colorHSV;
    private boolean colorPressed;
    private Bitmap colorWheelBitmap;
    private Paint colorWheelPaint;
    private int colorWheelRadius;
    private final ColorPickerDelegate delegate;
    private float[] hsvTemp;
    boolean ignoreTextChange;
    private LinearLayout linearLayout;
    private int lx;
    private int ly;
    private BrightnessLimit maxBrightness;
    private BrightnessLimit minBrightness;
    private final int paramValueSliderWidth;
    private Paint valueSliderPaint;

    public interface BrightnessLimit {
        float getLimit(int i, int i2, int i3);
    }

    public interface ColorPickerDelegate {
        void setColor(int i);
    }

    public ColorPicker(Context context, final ColorPickerDelegate delegate) {
        super(context);
        this.paramValueSliderWidth = AndroidUtilities.dp(20.0f);
        this.colorEditText = new EditTextBoldCursor[2];
        this.colorHSV = new float[]{0.0f, 0.0f, 1.0f};
        this.hsvTemp = new float[3];
        this.delegate = delegate;
        setWillNotDraw(false);
        this.circlePaint = new Paint(1);
        this.circleDrawable = context.getResources().getDrawable(R.drawable.knob_shadow).mutate();
        Paint paint = new Paint();
        this.colorWheelPaint = paint;
        paint.setAntiAlias(true);
        this.colorWheelPaint.setDither(true);
        Paint paint2 = new Paint();
        this.valueSliderPaint = paint2;
        paint2.setAntiAlias(true);
        this.valueSliderPaint.setDither(true);
        LinearLayout linearLayout = new LinearLayout(context);
        this.linearLayout = linearLayout;
        linearLayout.setOrientation(0);
        addView(this.linearLayout, LayoutHelper.createFrame(-1.0f, 46.0f, 51, 12.0f, 20.0f, 21.0f, 14.0f));
        int a = 0;
        while (a < 2) {
            final int num = a;
            this.colorEditText[a] = new EditTextBoldCursor(context);
            this.colorEditText[a].setTextSize(1, 18.0f);
            this.colorEditText[a].setHintColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.colorEditText[a].setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.colorEditText[a].setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
            this.colorEditText[a].setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.colorEditText[a].setCursorSize(AndroidUtilities.dp(20.0f));
            this.colorEditText[a].setCursorWidth(1.5f);
            this.colorEditText[a].setSingleLine(true);
            this.colorEditText[a].setGravity(19);
            this.colorEditText[a].setHeaderHintColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
            this.colorEditText[a].setTransformHintToHeader(true);
            if (a != 0) {
                this.colorEditText[a].setInputType(2);
                this.colorEditText[a].setHintText(LocaleController.getString("BackgroundBrightness", R.string.BackgroundBrightness));
            } else {
                this.colorEditText[a].setInputType(1);
                this.colorEditText[a].setHintText(LocaleController.getString("BackgroundHexColorCode", R.string.BackgroundHexColorCode));
            }
            this.colorEditText[a].setImeOptions(268435462);
            InputFilter[] inputFilters = new InputFilter[1];
            inputFilters[0] = new InputFilter.LengthFilter(a == 0 ? 7 : 3);
            this.colorEditText[a].setFilters(inputFilters);
            this.colorEditText[a].setPadding(0, AndroidUtilities.dp(6.0f), 0, 0);
            this.linearLayout.addView(this.colorEditText[a], LayoutHelper.createLinear(0, -1, a == 0 ? 0.67f : 0.31f, 0, 0, a != 1 ? 23 : 0, 0));
            this.colorEditText[a].addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.ColorPicker.1
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable editable) {
                    if (ColorPicker.this.ignoreTextChange) {
                        return;
                    }
                    ColorPicker.this.ignoreTextChange = true;
                    if (num == 0) {
                        int a2 = 0;
                        while (a2 < editable.length()) {
                            char ch = editable.charAt(a2);
                            if ((ch < '0' || ch > '9') && ((ch < 'a' || ch > 'f') && ((ch < 'A' || ch > 'F') && (ch != '#' || a2 != 0)))) {
                                editable.replace(a2, a2 + 1, "");
                                a2--;
                            }
                            a2++;
                        }
                        int a3 = editable.length();
                        if (a3 == 0) {
                            editable.append("#");
                        } else if (editable.charAt(0) != '#') {
                            editable.insert(0, "#");
                        }
                        if (editable.length() != 7) {
                            ColorPicker.this.ignoreTextChange = false;
                            return;
                        } else {
                            try {
                                ColorPicker.this.setColor(Integer.parseInt(editable.toString().substring(1), 16) | (-16777216));
                            } catch (Exception e) {
                                ColorPicker.this.setColor(-1);
                            }
                        }
                    } else {
                        int value = Utilities.parseInt(editable.toString()).intValue();
                        if (value > 255 || value < 0) {
                            if (value > 255) {
                                value = 255;
                            } else {
                                value = 0;
                            }
                            editable.replace(0, editable.length(), "" + value);
                        }
                        ColorPicker.this.colorHSV[2] = value / 255.0f;
                    }
                    int color = ColorPicker.this.getColor();
                    int red = Color.red(color);
                    int green = Color.green(color);
                    int blue = Color.blue(color);
                    ColorPicker.this.colorEditText[0].setTextKeepState(String.format("#%02x%02x%02x", Byte.valueOf((byte) red), Byte.valueOf((byte) green), Byte.valueOf((byte) blue)).toUpperCase());
                    ColorPicker.this.colorEditText[1].setTextKeepState(String.valueOf((int) (ColorPicker.this.getBrightness() * 255.0f)));
                    delegate.setColor(color);
                    ColorPicker.this.ignoreTextChange = false;
                }
            });
            this.colorEditText[a].setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ColorPicker$8tCSRBn7NZUl-DFMtrJsFYXf-zM
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                    return ColorPicker.lambda$new$0(textView, i, keyEvent);
                }
            });
            a++;
        }
    }

    static /* synthetic */ boolean lambda$new$0(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 6) {
            AndroidUtilities.hideKeyboard(textView);
            return true;
        }
        return false;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        int size = Math.min(widthSize, heightSize);
        measureChild(this.linearLayout, View.MeasureSpec.makeMeasureSpec(widthSize - AndroidUtilities.dp(42.0f), 1073741824), heightMeasureSpec);
        setMeasuredDimension(size, size);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        this.centerX = ((getWidth() / 2) - (this.paramValueSliderWidth * 2)) + AndroidUtilities.dp(11.0f);
        this.centerY = (getHeight() / 2) + AndroidUtilities.dp(34.0f);
        Bitmap bitmap = this.colorWheelBitmap;
        int i = this.centerX;
        int i2 = this.colorWheelRadius;
        canvas.drawBitmap(bitmap, i - i2, r1 - i2, (Paint) null);
        float hueAngle = (float) Math.toRadians(this.colorHSV[0]);
        int colorPointX = ((int) ((-Math.cos(hueAngle)) * ((double) this.colorHSV[1]) * ((double) this.colorWheelRadius))) + this.centerX;
        double d = -Math.sin(hueAngle);
        float[] fArr = this.colorHSV;
        int colorPointY = ((int) (d * ((double) fArr[1]) * ((double) this.colorWheelRadius))) + this.centerY;
        float[] fArr2 = this.hsvTemp;
        fArr2[0] = fArr[0];
        fArr2[1] = fArr[1];
        fArr2[2] = 1.0f;
        drawPointerArrow(canvas, colorPointX, colorPointY, Color.HSVToColor(fArr2));
        int i3 = this.centerX;
        int i4 = this.colorWheelRadius;
        this.lx = i3 + i4 + (this.paramValueSliderWidth * 2);
        this.ly = this.centerY - i4;
        int width = AndroidUtilities.dp(9.0f);
        int height = this.colorWheelRadius * 2;
        if (this.colorGradient == null) {
            this.colorGradient = new LinearGradient(this.lx, this.ly, r4 + width, r5 + height, new int[]{-16777216, Color.HSVToColor(this.hsvTemp)}, (float[]) null, Shader.TileMode.CLAMP);
        }
        this.valueSliderPaint.setShader(this.colorGradient);
        canvas.drawRect(this.lx, this.ly, r1 + width, r3 + height, this.valueSliderPaint);
        drawPointerArrow(canvas, this.lx + (width / 2), (int) (this.ly + (getBrightness() * height)), getColor());
    }

    private void drawPointerArrow(Canvas canvas, int x, int y, int color) {
        int side = AndroidUtilities.dp(13.0f);
        this.circleDrawable.setBounds(x - side, y - side, x + side, y + side);
        this.circleDrawable.draw(canvas);
        this.circlePaint.setColor(-1);
        canvas.drawCircle(x, y, AndroidUtilities.dp(11.0f), this.circlePaint);
        this.circlePaint.setColor(color);
        canvas.drawCircle(x, y, AndroidUtilities.dp(9.0f), this.circlePaint);
    }

    @Override // android.view.View
    protected void onSizeChanged(int width, int height, int oldw, int oldh) {
        if (this.colorWheelRadius != AndroidUtilities.dp(120.0f)) {
            int iDp = AndroidUtilities.dp(120.0f);
            this.colorWheelRadius = iDp;
            this.colorWheelBitmap = createColorWheelBitmap(iDp * 2, iDp * 2);
            this.colorGradient = null;
        }
    }

    private Bitmap createColorWheelBitmap(int width, int height) {
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        int[] colors = new int[12 + 1];
        float[] hsv = {0.0f, 1.0f, 1.0f};
        for (int i = 0; i < colors.length; i++) {
            hsv[0] = ((i * 30) + JavaScreenCapturer.DEGREE_180) % 360;
            colors[i] = Color.HSVToColor(hsv);
        }
        int i2 = colors[0];
        colors[12] = i2;
        SweepGradient sweepGradient = new SweepGradient(width * 0.5f, height * 0.5f, colors, (float[]) null);
        RadialGradient radialGradient = new RadialGradient(width * 0.5f, height * 0.5f, this.colorWheelRadius, -1, ViewCompat.MEASURED_SIZE_MASK, Shader.TileMode.CLAMP);
        ComposeShader composeShader = new ComposeShader(sweepGradient, radialGradient, PorterDuff.Mode.SRC_OVER);
        this.colorWheelPaint.setShader(composeShader);
        Canvas canvas = new Canvas(bitmap);
        canvas.drawCircle(width * 0.5f, height * 0.5f, this.colorWheelRadius, this.colorWheelPaint);
        return bitmap;
    }

    /* JADX WARN: Code restructure failed: missing block: B:5:0x000d, code lost:
    
        if (r1 != 2) goto L8;
     */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r19) {
        /*
            Method dump skipped, instruction units count: 350
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ColorPicker.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public void setColor(int color) {
        if (!this.ignoreTextChange) {
            this.ignoreTextChange = true;
            int red = Color.red(color);
            int green = Color.green(color);
            int blue = Color.blue(color);
            Color.colorToHSV(color, this.colorHSV);
            this.colorEditText[0].setText(String.format("#%02x%02x%02x", Byte.valueOf((byte) red), Byte.valueOf((byte) green), Byte.valueOf((byte) blue)).toUpperCase());
            this.colorEditText[1].setText(String.valueOf((int) (getBrightness() * 255.0f)));
            for (int b = 0; b < 2; b++) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.colorEditText;
                editTextBoldCursorArr[b].setSelection(editTextBoldCursorArr[b].length());
            }
            this.ignoreTextChange = false;
        } else {
            Color.colorToHSV(color, this.colorHSV);
        }
        this.colorGradient = null;
        invalidate();
    }

    public int getColor() {
        float[] fArr = this.hsvTemp;
        float[] fArr2 = this.colorHSV;
        fArr[0] = fArr2[0];
        fArr[1] = fArr2[1];
        fArr[2] = getBrightness();
        return (Color.HSVToColor(this.hsvTemp) & ViewCompat.MEASURED_SIZE_MASK) | (-16777216);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getBrightness() {
        float[] fArr = this.colorHSV;
        float brightness = fArr[2];
        fArr[2] = 1.0f;
        int color = Color.HSVToColor(fArr);
        int red = Color.red(color);
        int green = Color.green(color);
        int blue = Color.blue(color);
        this.colorHSV[2] = brightness;
        BrightnessLimit brightnessLimit = this.minBrightness;
        float min = brightnessLimit == null ? 0.0f : brightnessLimit.getLimit(red, green, blue);
        BrightnessLimit brightnessLimit2 = this.maxBrightness;
        float max = brightnessLimit2 != null ? brightnessLimit2.getLimit(red, green, blue) : 1.0f;
        return Math.max(min, Math.min(brightness, max));
    }

    public void setMinBrightness(BrightnessLimit limit) {
        this.minBrightness = limit;
    }

    public void setMaxBrightness(BrightnessLimit limit) {
        this.maxBrightness = limit;
    }

    public void provideThemeDescriptions(List<ThemeDescription> arrayList) {
        int a = 0;
        while (true) {
            EditTextBoldCursor[] editTextBoldCursorArr = this.colorEditText;
            if (a < editTextBoldCursorArr.length) {
                arrayList.add(new ThemeDescription(editTextBoldCursorArr[a], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(this.colorEditText[a], ThemeDescription.FLAG_CURSORCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(this.colorEditText[a], ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(this.colorEditText[a], ThemeDescription.FLAG_HINTTEXTCOLOR | ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));
                arrayList.add(new ThemeDescription(this.colorEditText[a], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(this.colorEditText[a], ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                a++;
            } else {
                return;
            }
        }
    }
}
