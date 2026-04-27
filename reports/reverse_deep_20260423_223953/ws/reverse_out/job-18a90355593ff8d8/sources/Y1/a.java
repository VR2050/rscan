package Y1;

import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;

/* JADX INFO: loaded from: classes.dex */
public final class a extends MetricAffectingSpan implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2879a;

    public a(float f3) {
        this.f2879a = f3;
    }

    private final void a(TextPaint textPaint) {
        if (Float.isNaN(this.f2879a)) {
            return;
        }
        textPaint.setLetterSpacing(this.f2879a);
    }

    public final float b() {
        return this.f2879a;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        t2.j.f(textPaint, "paint");
        a(textPaint);
    }

    @Override // android.text.style.MetricAffectingSpan
    public void updateMeasureState(TextPaint textPaint) {
        t2.j.f(textPaint, "paint");
        a(textPaint);
    }
}
