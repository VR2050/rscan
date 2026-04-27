package Y1;

import android.text.TextPaint;

/* JADX INFO: loaded from: classes.dex */
public final class l implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final TextPaint f2892a;

    public l(TextPaint textPaint) {
        t2.j.f(textPaint, "textPaint");
        this.f2892a = textPaint;
    }

    public final TextPaint a() {
        return this.f2892a;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && t2.j.b(this.f2892a, ((l) obj).f2892a);
    }

    public int hashCode() {
        return this.f2892a.hashCode();
    }

    public String toString() {
        return "ReactTextPaintHolderSpan(textPaint=" + this.f2892a + ")";
    }
}
