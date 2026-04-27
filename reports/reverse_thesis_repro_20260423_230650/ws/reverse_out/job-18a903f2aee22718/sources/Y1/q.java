package Y1;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.style.ReplacementSpan;

/* JADX INFO: loaded from: classes.dex */
public final class q extends ReplacementSpan implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2902a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2903b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f2904c;

    public q(int i3, int i4, int i5) {
        this.f2902a = i3;
        this.f2903b = i4;
        this.f2904c = i5;
    }

    public final int a() {
        return this.f2904c;
    }

    public final int b() {
        return this.f2902a;
    }

    public final int c() {
        return this.f2903b;
    }

    @Override // android.text.style.ReplacementSpan
    public void draw(Canvas canvas, CharSequence charSequence, int i3, int i4, float f3, int i5, int i6, int i7, Paint paint) {
        t2.j.f(canvas, "canvas");
        t2.j.f(paint, "paint");
    }

    @Override // android.text.style.ReplacementSpan
    public int getSize(Paint paint, CharSequence charSequence, int i3, int i4, Paint.FontMetricsInt fontMetricsInt) {
        t2.j.f(paint, "paint");
        if (fontMetricsInt != null) {
            int i5 = -this.f2904c;
            fontMetricsInt.ascent = i5;
            fontMetricsInt.descent = 0;
            fontMetricsInt.top = i5;
            fontMetricsInt.bottom = 0;
        }
        return this.f2903b;
    }
}
