package Y1;

import android.text.TextPaint;
import android.text.style.CharacterStyle;

/* JADX INFO: loaded from: classes.dex */
public final class o extends CharacterStyle implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2897a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f2898b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f2899c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f2900d;

    public o(float f3, float f4, float f5, int i3) {
        this.f2897a = f3;
        this.f2898b = f4;
        this.f2899c = f5;
        this.f2900d = i3;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        t2.j.f(textPaint, "textPaint");
        textPaint.setShadowLayer(this.f2899c, this.f2897a, this.f2898b, this.f2900d);
    }
}
