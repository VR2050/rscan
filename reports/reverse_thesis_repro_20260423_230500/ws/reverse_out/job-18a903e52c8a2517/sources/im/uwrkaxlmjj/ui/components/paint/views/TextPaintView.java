package im.uwrkaxlmjj.ui.components.paint.views;

import android.content.Context;
import android.graphics.Canvas;
import android.os.Build;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.Point;
import im.uwrkaxlmjj.ui.components.Rect;
import im.uwrkaxlmjj.ui.components.paint.Swatch;
import im.uwrkaxlmjj.ui.components.paint.views.EntityView;

/* JADX INFO: loaded from: classes5.dex */
public class TextPaintView extends EntityView {
    private int baseFontSize;
    private EditTextOutline editText;
    private boolean stroke;
    private Swatch swatch;

    public TextPaintView(Context context, Point position, int fontSize, String text, Swatch swatch, boolean stroke) {
        super(context, position);
        this.baseFontSize = fontSize;
        EditTextOutline editTextOutline = new EditTextOutline(context);
        this.editText = editTextOutline;
        editTextOutline.setBackgroundColor(0);
        this.editText.setPadding(AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f));
        this.editText.setClickable(false);
        this.editText.setEnabled(false);
        this.editText.setTextSize(0, this.baseFontSize);
        this.editText.setText(text);
        this.editText.setTextColor(swatch.color);
        this.editText.setTypeface(null, 1);
        this.editText.setGravity(17);
        this.editText.setHorizontallyScrolling(false);
        this.editText.setImeOptions(C.ENCODING_PCM_MU_LAW);
        this.editText.setFocusableInTouchMode(true);
        EditTextOutline editTextOutline2 = this.editText;
        editTextOutline2.setInputType(editTextOutline2.getInputType() | 16384);
        addView(this.editText, LayoutHelper.createFrame(-2, -2, 51));
        if (Build.VERSION.SDK_INT >= 23) {
            this.editText.setBreakStrategy(0);
        }
        setSwatch(swatch);
        setStroke(stroke);
        updatePosition();
        this.editText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.paint.views.TextPaintView.1
            private int beforeCursorPosition = 0;
            private String text;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                this.text = s.toString();
                this.beforeCursorPosition = start;
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                TextPaintView.this.editText.removeTextChangedListener(this);
                if (TextPaintView.this.editText.getLineCount() > 9) {
                    TextPaintView.this.editText.setText(this.text);
                    TextPaintView.this.editText.setSelection(this.beforeCursorPosition);
                }
                TextPaintView.this.editText.addTextChangedListener(this);
            }
        });
    }

    public TextPaintView(Context context, TextPaintView textPaintView, Point position) {
        this(context, position, textPaintView.baseFontSize, textPaintView.getText(), textPaintView.getSwatch(), textPaintView.stroke);
        setRotation(textPaintView.getRotation());
        setScale(textPaintView.getScale());
    }

    public void setMaxWidth(int maxWidth) {
        this.editText.setMaxWidth(maxWidth);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        updatePosition();
    }

    public String getText() {
        return this.editText.getText().toString();
    }

    public void setText(String text) {
        this.editText.setText(text);
    }

    public View getFocusedView() {
        return this.editText;
    }

    public void beginEditing() {
        this.editText.setEnabled(true);
        this.editText.setClickable(true);
        this.editText.requestFocus();
        EditTextOutline editTextOutline = this.editText;
        editTextOutline.setSelection(editTextOutline.getText().length());
    }

    public void endEditing() {
        this.editText.clearFocus();
        this.editText.setEnabled(false);
        this.editText.setClickable(false);
        updateSelectionView();
    }

    public Swatch getSwatch() {
        return this.swatch;
    }

    public void setSwatch(Swatch swatch) {
        this.swatch = swatch;
        updateColor();
    }

    public void setStroke(boolean stroke) {
        this.stroke = stroke;
        updateColor();
    }

    private void updateColor() {
        if (this.stroke) {
            this.editText.setTextColor(-1);
            this.editText.setStrokeColor(this.swatch.color);
            this.editText.setShadowLayer(0.0f, 0.0f, 0.0f, 0);
        } else {
            this.editText.setTextColor(this.swatch.color);
            this.editText.setStrokeColor(0);
            this.editText.setShadowLayer(8.0f, 0.0f, 2.0f, -1442840576);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView
    protected Rect getSelectionBounds() {
        ViewGroup parentView = (ViewGroup) getParent();
        float scale = parentView.getScaleX();
        float width = (getWidth() * getScale()) + (AndroidUtilities.dp(46.0f) / scale);
        float height = (getHeight() * getScale()) + (AndroidUtilities.dp(20.0f) / scale);
        return new Rect((this.position.x - (width / 2.0f)) * scale, (this.position.y - (height / 2.0f)) * scale, width * scale, height * scale);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView
    public TextViewSelectionView createSelectionView() {
        return new TextViewSelectionView(getContext());
    }

    public class TextViewSelectionView extends EntityView.SelectionView {
        public TextViewSelectionView(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView.SelectionView
        protected int pointInsideHandle(float x, float y) {
            float thickness = AndroidUtilities.dp(1.0f);
            float radius = AndroidUtilities.dp(19.5f);
            float inset = radius + thickness;
            float width = getWidth() - (inset * 2.0f);
            float height = getHeight() - (inset * 2.0f);
            float middle = (height / 2.0f) + inset;
            if (x > inset - radius && y > middle - radius && x < inset + radius && y < middle + radius) {
                return 1;
            }
            if (x > (inset + width) - radius && y > middle - radius && x < inset + width + radius && y < middle + radius) {
                return 2;
            }
            if (x > inset && x < width && y > inset && y < height) {
                return 3;
            }
            return 0;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float space = AndroidUtilities.dp(3.0f);
            float length = AndroidUtilities.dp(3.0f);
            float thickness = AndroidUtilities.dp(1.0f);
            float radius = AndroidUtilities.dp(4.5f);
            float inset = radius + thickness + AndroidUtilities.dp(15.0f);
            float width = getWidth() - (inset * 2.0f);
            float height = getHeight() - (inset * 2.0f);
            int xCount = (int) Math.floor(width / (space + length));
            float xGap = (float) Math.ceil(((width - (xCount * (space + length))) + space) / 2.0f);
            int i = 0;
            while (i < xCount) {
                float x = xGap + inset + (i * (length + space));
                float xGap2 = x + length;
                canvas.drawRect(x, inset - (thickness / 2.0f), xGap2, inset + (thickness / 2.0f), this.paint);
                canvas.drawRect(x, (inset + height) - (thickness / 2.0f), x + length, inset + height + (thickness / 2.0f), this.paint);
                i++;
                xGap = xGap;
                xCount = xCount;
            }
            int yCount = (int) Math.floor(height / (space + length));
            float yGap = (float) Math.ceil(((height - (yCount * (space + length))) + space) / 2.0f);
            int i2 = 0;
            while (i2 < yCount) {
                float y = yGap + inset + (i2 * (length + space));
                float yGap2 = inset + (thickness / 2.0f);
                canvas.drawRect(inset - (thickness / 2.0f), y, yGap2, y + length, this.paint);
                canvas.drawRect((inset + width) - (thickness / 2.0f), y, inset + width + (thickness / 2.0f), y + length, this.paint);
                i2++;
                yGap = yGap;
                yCount = yCount;
            }
            canvas.drawCircle(inset, (height / 2.0f) + inset, radius, this.dotPaint);
            canvas.drawCircle(inset, (height / 2.0f) + inset, radius, this.dotStrokePaint);
            canvas.drawCircle(inset + width, (height / 2.0f) + inset, radius, this.dotPaint);
            canvas.drawCircle(inset + width, (height / 2.0f) + inset, radius, this.dotStrokePaint);
        }
    }
}
