package p429g.p430a.p431a.p432a;

import android.text.TextPaint;
import android.text.style.ClickableSpan;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: g.a.a.a.h */
/* loaded from: classes2.dex */
public abstract class AbstractC4333h extends ClickableSpan {

    /* renamed from: c */
    public boolean f11186c;

    /* renamed from: e */
    public final int f11187e;

    /* renamed from: f */
    public final int f11188f;

    public AbstractC4333h(int i2, int i3) {
        this.f11187e = i2;
        this.f11188f = i3;
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(@NotNull TextPaint textPaint) {
        Intrinsics.checkNotNullParameter(textPaint, "textPaint");
        super.updateDrawState(textPaint);
        int i2 = this.f11186c ? this.f11188f : this.f11187e;
        textPaint.setAntiAlias(true);
        textPaint.setColor(i2);
        textPaint.setUnderlineText(false);
        textPaint.bgColor = 0;
    }
}
