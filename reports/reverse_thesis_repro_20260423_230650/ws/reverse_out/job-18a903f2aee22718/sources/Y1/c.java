package Y1;

import android.content.res.AssetManager;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class c extends MetricAffectingSpan implements i {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f2881f = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2882a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2883b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f2884c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f2885d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final AssetManager f2886e;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void b(Paint paint, int i3, int i4, String str, String str2, AssetManager assetManager) {
            Typeface typefaceA = com.facebook.react.views.text.o.a(paint.getTypeface(), i3, i4, str2, assetManager);
            paint.setFontFeatureSettings(str);
            paint.setTypeface(typefaceA);
            paint.setSubpixelText(true);
        }

        private a() {
        }
    }

    public c(int i3, int i4, String str, String str2, AssetManager assetManager) {
        t2.j.f(assetManager, "assetManager");
        this.f2882a = i3;
        this.f2883b = i4;
        this.f2884c = str;
        this.f2885d = str2;
        this.f2886e = assetManager;
    }

    public final String a() {
        return this.f2885d;
    }

    public final String b() {
        return this.f2884c;
    }

    public final int c() {
        int i3 = this.f2882a;
        if (i3 == -1) {
            return 0;
        }
        return i3;
    }

    public final int d() {
        int i3 = this.f2883b;
        if (i3 == -1) {
            return 400;
        }
        return i3;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        t2.j.f(textPaint, "ds");
        f2881f.b(textPaint, this.f2882a, this.f2883b, this.f2884c, this.f2885d, this.f2886e);
    }

    @Override // android.text.style.MetricAffectingSpan
    public void updateMeasureState(TextPaint textPaint) {
        t2.j.f(textPaint, "paint");
        f2881f.b(textPaint, this.f2882a, this.f2883b, this.f2884c, this.f2885d, this.f2886e);
    }
}
