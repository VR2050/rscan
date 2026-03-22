package p005b.p081b0.p082a.p084b;

import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b0.a.b.c */
/* loaded from: classes2.dex */
public final class C1329c extends ClickableSpan {

    /* renamed from: c */
    public final int f1123c;

    /* renamed from: e */
    public final boolean f1124e;

    /* renamed from: f */
    @NotNull
    public Function0<Unit> f1125f;

    public C1329c(int i2, boolean z, int i3) {
        z = (i3 & 2) != 0 ? false : z;
        this.f1123c = i2;
        this.f1124e = z;
        this.f1125f = C1328b.f1122c;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(@NotNull View widget) {
        Intrinsics.checkNotNullParameter(widget, "widget");
        this.f1125f.invoke();
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(@NotNull TextPaint ds) {
        Intrinsics.checkNotNullParameter(ds, "ds");
        ds.setColor(this.f1123c);
        ds.setUnderlineText(this.f1124e);
        ds.bgColor = 0;
    }
}
