package Y1;

import android.graphics.Color;
import android.text.TextPaint;
import android.text.style.CharacterStyle;
import android.text.style.UpdateAppearance;

/* JADX INFO: loaded from: classes.dex */
public final class h extends CharacterStyle implements UpdateAppearance, i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2890a;

    public h(float f3) {
        this.f2890a = f3;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        t2.j.f(textPaint, "paint");
        textPaint.setAlpha(u2.a.c(Color.alpha(textPaint.getColor()) * this.f2890a));
        if (textPaint.bgColor != 0) {
            textPaint.bgColor = Color.argb(u2.a.c(Color.alpha(r0) * this.f2890a), Color.red(textPaint.bgColor), Color.green(textPaint.bgColor), Color.blue(textPaint.bgColor));
        }
    }
}
