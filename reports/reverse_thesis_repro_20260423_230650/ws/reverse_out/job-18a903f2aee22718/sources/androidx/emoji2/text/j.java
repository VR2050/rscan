package androidx.emoji2.text;

import android.graphics.Paint;
import android.text.style.ReplacementSpan;

/* JADX INFO: loaded from: classes.dex */
public abstract class j extends ReplacementSpan {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final p f4656b;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Paint.FontMetricsInt f4655a = new Paint.FontMetricsInt();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private short f4657c = -1;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private short f4658d = -1;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f4659e = 1.0f;

    j(p pVar) {
        q.g.g(pVar, "rasterizer cannot be null");
        this.f4656b = pVar;
    }

    public final p a() {
        return this.f4656b;
    }

    final int b() {
        return this.f4657c;
    }

    @Override // android.text.style.ReplacementSpan
    public int getSize(Paint paint, CharSequence charSequence, int i3, int i4, Paint.FontMetricsInt fontMetricsInt) {
        paint.getFontMetricsInt(this.f4655a);
        Paint.FontMetricsInt fontMetricsInt2 = this.f4655a;
        this.f4659e = (Math.abs(fontMetricsInt2.descent - fontMetricsInt2.ascent) * 1.0f) / this.f4656b.e();
        this.f4658d = (short) (this.f4656b.e() * this.f4659e);
        short sI = (short) (this.f4656b.i() * this.f4659e);
        this.f4657c = sI;
        if (fontMetricsInt != null) {
            Paint.FontMetricsInt fontMetricsInt3 = this.f4655a;
            fontMetricsInt.ascent = fontMetricsInt3.ascent;
            fontMetricsInt.descent = fontMetricsInt3.descent;
            fontMetricsInt.top = fontMetricsInt3.top;
            fontMetricsInt.bottom = fontMetricsInt3.bottom;
        }
        return sI;
    }
}
