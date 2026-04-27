package androidx.core.text;

import android.os.Build;
import android.text.PrecomputedText;
import android.text.Spannable;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.text.TextPaint;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes.dex */
public abstract class l implements Spannable {

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final TextPaint f4377a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final TextDirectionHeuristic f4378b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f4379c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f4380d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final PrecomputedText.Params f4381e;

        /* JADX INFO: renamed from: androidx.core.text.l$a$a, reason: collision with other inner class name */
        public static class C0063a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private final TextPaint f4382a;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            private int f4384c = 1;

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            private int f4385d = 1;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            private TextDirectionHeuristic f4383b = TextDirectionHeuristics.FIRSTSTRONG_LTR;

            public C0063a(TextPaint textPaint) {
                this.f4382a = textPaint;
            }

            public a a() {
                return new a(this.f4382a, this.f4383b, this.f4384c, this.f4385d);
            }

            public C0063a b(int i3) {
                this.f4384c = i3;
                return this;
            }

            public C0063a c(int i3) {
                this.f4385d = i3;
                return this;
            }

            public C0063a d(TextDirectionHeuristic textDirectionHeuristic) {
                this.f4383b = textDirectionHeuristic;
                return this;
            }
        }

        a(TextPaint textPaint, TextDirectionHeuristic textDirectionHeuristic, int i3, int i4) {
            if (Build.VERSION.SDK_INT >= 29) {
                this.f4381e = k.a(textPaint).setBreakStrategy(i3).setHyphenationFrequency(i4).setTextDirection(textDirectionHeuristic).build();
            } else {
                this.f4381e = null;
            }
            this.f4377a = textPaint;
            this.f4378b = textDirectionHeuristic;
            this.f4379c = i3;
            this.f4380d = i4;
        }

        public boolean a(a aVar) {
            if (this.f4379c == aVar.b() && this.f4380d == aVar.c() && this.f4377a.getTextSize() == aVar.e().getTextSize() && this.f4377a.getTextScaleX() == aVar.e().getTextScaleX() && this.f4377a.getTextSkewX() == aVar.e().getTextSkewX() && this.f4377a.getLetterSpacing() == aVar.e().getLetterSpacing() && TextUtils.equals(this.f4377a.getFontFeatureSettings(), aVar.e().getFontFeatureSettings()) && this.f4377a.getFlags() == aVar.e().getFlags() && this.f4377a.getTextLocales().equals(aVar.e().getTextLocales())) {
                return this.f4377a.getTypeface() == null ? aVar.e().getTypeface() == null : this.f4377a.getTypeface().equals(aVar.e().getTypeface());
            }
            return false;
        }

        public int b() {
            return this.f4379c;
        }

        public int c() {
            return this.f4380d;
        }

        public TextDirectionHeuristic d() {
            return this.f4378b;
        }

        public TextPaint e() {
            return this.f4377a;
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof a)) {
                return false;
            }
            a aVar = (a) obj;
            return a(aVar) && this.f4378b == aVar.d();
        }

        public int hashCode() {
            return q.c.b(Float.valueOf(this.f4377a.getTextSize()), Float.valueOf(this.f4377a.getTextScaleX()), Float.valueOf(this.f4377a.getTextSkewX()), Float.valueOf(this.f4377a.getLetterSpacing()), Integer.valueOf(this.f4377a.getFlags()), this.f4377a.getTextLocales(), this.f4377a.getTypeface(), Boolean.valueOf(this.f4377a.isElegantTextHeight()), this.f4378b, Integer.valueOf(this.f4379c), Integer.valueOf(this.f4380d));
        }

        public String toString() {
            StringBuilder sb = new StringBuilder("{");
            sb.append("textSize=" + this.f4377a.getTextSize());
            sb.append(", textScaleX=" + this.f4377a.getTextScaleX());
            sb.append(", textSkewX=" + this.f4377a.getTextSkewX());
            int i3 = Build.VERSION.SDK_INT;
            sb.append(", letterSpacing=" + this.f4377a.getLetterSpacing());
            sb.append(", elegantTextHeight=" + this.f4377a.isElegantTextHeight());
            sb.append(", textLocale=" + this.f4377a.getTextLocales());
            sb.append(", typeface=" + this.f4377a.getTypeface());
            if (i3 >= 26) {
                sb.append(", variationSettings=" + this.f4377a.getFontVariationSettings());
            }
            sb.append(", textDir=" + this.f4378b);
            sb.append(", breakStrategy=" + this.f4379c);
            sb.append(", hyphenationFrequency=" + this.f4380d);
            sb.append("}");
            return sb.toString();
        }

        public a(PrecomputedText.Params params) {
            this.f4377a = params.getTextPaint();
            this.f4378b = params.getTextDirection();
            this.f4379c = params.getBreakStrategy();
            this.f4380d = params.getHyphenationFrequency();
            this.f4381e = Build.VERSION.SDK_INT < 29 ? null : params;
        }
    }
}
