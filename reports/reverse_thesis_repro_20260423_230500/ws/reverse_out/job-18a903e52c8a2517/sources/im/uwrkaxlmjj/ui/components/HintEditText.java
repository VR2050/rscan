package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class HintEditText extends EditTextBoldCursor {
    private String hintText;
    private float numberSize;
    private Paint paint;
    private android.graphics.Rect rect;
    private float spaceSize;
    private float textOffset;

    public HintEditText(Context context) {
        super(context);
        this.paint = new Paint();
        this.rect = new android.graphics.Rect();
        this.paint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
    }

    public String getHintText() {
        return this.hintText;
    }

    public void setHintText(String value) {
        this.hintText = value;
        onTextChange();
        setText(getText());
    }

    @Override // android.widget.TextView, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        onTextChange();
    }

    public void onTextChange() {
        this.textOffset = length() > 0 ? getPaint().measureText(getText(), 0, length()) : 0.0f;
        this.spaceSize = getPaint().measureText(" ");
        this.numberSize = getPaint().measureText("1");
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        float f;
        super.onDraw(canvas);
        if (this.hintText != null && length() < this.hintText.length()) {
            int top = getMeasuredHeight() / 2;
            float offsetX = this.textOffset;
            for (int a = length(); a < this.hintText.length(); a++) {
                if (this.hintText.charAt(a) == ' ') {
                    f = this.spaceSize;
                } else {
                    this.rect.set(((int) offsetX) + AndroidUtilities.dp(1.0f), top, ((int) (this.numberSize + offsetX)) - AndroidUtilities.dp(1.0f), AndroidUtilities.dp(2.0f) + top);
                    canvas.drawRect(this.rect, this.paint);
                    f = this.numberSize;
                }
                offsetX += f;
            }
        }
    }
}
