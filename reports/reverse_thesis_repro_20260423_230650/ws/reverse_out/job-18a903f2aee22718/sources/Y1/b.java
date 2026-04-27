package Y1;

import android.graphics.Paint;
import android.text.style.LineHeightSpan;

/* JADX INFO: loaded from: classes.dex */
public final class b implements LineHeightSpan, i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2880a;

    public b(float f3) {
        this.f2880a = (int) Math.ceil(f3);
    }

    @Override // android.text.style.LineHeightSpan
    public void chooseHeight(CharSequence charSequence, int i3, int i4, int i5, int i6, Paint.FontMetricsInt fontMetricsInt) {
        t2.j.f(charSequence, "text");
        t2.j.f(fontMetricsInt, "fm");
        int i7 = this.f2880a;
        double d3 = (i7 - ((-r9) + fontMetricsInt.descent)) / 2.0f;
        fontMetricsInt.ascent = fontMetricsInt.ascent - ((int) Math.ceil(d3));
        fontMetricsInt.descent += (int) Math.floor(d3);
        if (i3 == 0) {
            fontMetricsInt.top = fontMetricsInt.ascent;
        }
        if (i4 == charSequence.length()) {
            fontMetricsInt.bottom = fontMetricsInt.descent;
        }
    }
}
