package androidx.emoji2.text;

import android.os.Build;
import android.text.Spannable;
import android.text.SpannableString;
import java.util.stream.IntStream;

/* JADX INFO: loaded from: classes.dex */
class r implements Spannable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f4691b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Spannable f4692c;

    private static class a {
        static IntStream a(CharSequence charSequence) {
            return charSequence.chars();
        }

        static IntStream b(CharSequence charSequence) {
            return charSequence.codePoints();
        }
    }

    static class b {
        b() {
        }

        boolean a(CharSequence charSequence) {
            return false;
        }
    }

    static class c extends b {
        c() {
        }

        @Override // androidx.emoji2.text.r.b
        boolean a(CharSequence charSequence) {
            return s.a(charSequence);
        }
    }

    r(Spannable spannable) {
        this.f4692c = spannable;
    }

    private void a() {
        Spannable spannable = this.f4692c;
        if (!this.f4691b && c().a(spannable)) {
            this.f4692c = new SpannableString(spannable);
        }
        this.f4691b = true;
    }

    static b c() {
        return Build.VERSION.SDK_INT < 28 ? new b() : new c();
    }

    Spannable b() {
        return this.f4692c;
    }

    @Override // java.lang.CharSequence
    public char charAt(int i3) {
        return this.f4692c.charAt(i3);
    }

    @Override // java.lang.CharSequence
    public IntStream chars() {
        return a.a(this.f4692c);
    }

    @Override // java.lang.CharSequence
    public IntStream codePoints() {
        return a.b(this.f4692c);
    }

    @Override // android.text.Spanned
    public int getSpanEnd(Object obj) {
        return this.f4692c.getSpanEnd(obj);
    }

    @Override // android.text.Spanned
    public int getSpanFlags(Object obj) {
        return this.f4692c.getSpanFlags(obj);
    }

    @Override // android.text.Spanned
    public int getSpanStart(Object obj) {
        return this.f4692c.getSpanStart(obj);
    }

    @Override // android.text.Spanned
    public Object[] getSpans(int i3, int i4, Class cls) {
        return this.f4692c.getSpans(i3, i4, cls);
    }

    @Override // java.lang.CharSequence
    public int length() {
        return this.f4692c.length();
    }

    @Override // android.text.Spanned
    public int nextSpanTransition(int i3, int i4, Class cls) {
        return this.f4692c.nextSpanTransition(i3, i4, cls);
    }

    @Override // android.text.Spannable
    public void removeSpan(Object obj) {
        a();
        this.f4692c.removeSpan(obj);
    }

    @Override // android.text.Spannable
    public void setSpan(Object obj, int i3, int i4, int i5) {
        a();
        this.f4692c.setSpan(obj, i3, i4, i5);
    }

    @Override // java.lang.CharSequence
    public CharSequence subSequence(int i3, int i4) {
        return this.f4692c.subSequence(i3, i4);
    }

    @Override // java.lang.CharSequence
    public String toString() {
        return this.f4692c.toString();
    }

    r(CharSequence charSequence) {
        this.f4692c = new SpannableString(charSequence);
    }
}
