package androidx.emoji2.text;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.style.CharacterStyle;

/* JADX INFO: loaded from: classes.dex */
public final class q extends j {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static Paint f4689g;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private TextPaint f4690f;

    public q(p pVar) {
        super(pVar);
    }

    private TextPaint c(CharSequence charSequence, int i3, int i4, Paint paint) {
        if (!(charSequence instanceof Spanned)) {
            if (paint instanceof TextPaint) {
                return (TextPaint) paint;
            }
            return null;
        }
        CharacterStyle[] characterStyleArr = (CharacterStyle[]) ((Spanned) charSequence).getSpans(i3, i4, CharacterStyle.class);
        if (characterStyleArr.length != 0) {
            if (characterStyleArr.length != 1 || characterStyleArr[0] != this) {
                TextPaint textPaint = this.f4690f;
                if (textPaint == null) {
                    textPaint = new TextPaint();
                    this.f4690f = textPaint;
                }
                textPaint.set(paint);
                for (CharacterStyle characterStyle : characterStyleArr) {
                    characterStyle.updateDrawState(textPaint);
                }
                return textPaint;
            }
        }
        if (paint instanceof TextPaint) {
            return (TextPaint) paint;
        }
        return null;
    }

    private static Paint e() {
        if (f4689g == null) {
            TextPaint textPaint = new TextPaint();
            f4689g = textPaint;
            textPaint.setColor(f.c().d());
            f4689g.setStyle(Paint.Style.FILL);
        }
        return f4689g;
    }

    void d(Canvas canvas, TextPaint textPaint, float f3, float f4, float f5, float f6) {
        int color = textPaint.getColor();
        Paint.Style style = textPaint.getStyle();
        textPaint.setColor(textPaint.bgColor);
        textPaint.setStyle(Paint.Style.FILL);
        canvas.drawRect(f3, f5, f4, f6, textPaint);
        textPaint.setStyle(style);
        textPaint.setColor(color);
    }

    @Override // android.text.style.ReplacementSpan
    public void draw(Canvas canvas, CharSequence charSequence, int i3, int i4, float f3, int i5, int i6, int i7, Paint paint) {
        Paint paint2 = paint;
        TextPaint textPaintC = c(charSequence, i3, i4, paint2);
        if (textPaintC != null && textPaintC.bgColor != 0) {
            d(canvas, textPaintC, f3, f3 + b(), i5, i7);
        }
        if (f.c().j()) {
            canvas.drawRect(f3, i5, f3 + b(), i7, e());
        }
        p pVarA = a();
        float f4 = i6;
        if (textPaintC != null) {
            paint2 = textPaintC;
        }
        pVarA.a(canvas, f3, f4, paint2);
    }
}
