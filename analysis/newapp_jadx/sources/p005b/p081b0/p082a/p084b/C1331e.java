package p005b.p081b0.p082a.p084b;

import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.NinePatchDrawable;
import android.text.style.ReplacementSpan;
import android.widget.TextView;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Lazy;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p166q.p167i.AbstractC1784c;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;

/* renamed from: b.b0.a.b.e */
/* loaded from: classes2.dex */
public final class C1331e extends ReplacementSpan {

    /* renamed from: c */
    @NotNull
    public final TextView f1126c;

    /* renamed from: e */
    @NotNull
    public final Object f1127e;

    /* renamed from: f */
    public int f1128f;

    /* renamed from: g */
    public int f1129g;

    /* renamed from: h */
    public int f1130h;

    /* renamed from: i */
    public int f1131i;

    /* renamed from: j */
    @NotNull
    public Rect f1132j;

    /* renamed from: k */
    @NotNull
    public Rect f1133k;

    /* renamed from: l */
    public int f1134l;

    /* renamed from: m */
    public int f1135m;

    /* renamed from: n */
    @NotNull
    public AtomicReference<Drawable> f1136n;

    /* renamed from: o */
    @NotNull
    public C1779f f1137o;

    /* renamed from: p */
    @NotNull
    public Rect f1138p;

    /* renamed from: q */
    @Nullable
    public InterfaceC1775b f1139q;

    /* renamed from: r */
    @NotNull
    public final Lazy f1140r;

    /* renamed from: s */
    @NotNull
    public final C1330d f1141s;

    /* renamed from: b.b0.a.b.e$a */
    public static final class a extends AbstractC1784c<Drawable> {
        public a(int i2, int i3) {
            super(i2, i3);
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadCleared(@Nullable Drawable drawable) {
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1784c, p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadFailed(@Nullable Drawable drawable) {
            if (drawable == null || Intrinsics.areEqual(drawable, C1331e.this.f1136n.get())) {
                return;
            }
            C1331e.m337a(C1331e.this, drawable);
            C1331e.this.f1136n.set(drawable);
            C1331e.this.f1126c.invalidate();
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1784c, p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadStarted(@Nullable Drawable drawable) {
            if (drawable != null) {
                C1331e.m337a(C1331e.this, drawable);
                C1331e.this.f1136n.set(drawable);
            }
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onResourceReady(Object obj, InterfaceC1793b interfaceC1793b) {
            Drawable resource = (Drawable) obj;
            Intrinsics.checkNotNullParameter(resource, "resource");
            if (resource instanceof GifDrawable) {
                GifDrawable gifDrawable = (GifDrawable) resource;
                gifDrawable.setCallback(C1331e.this.f1141s);
                int i2 = C1331e.this.f1128f;
                if (i2 <= 0 && i2 != -1 && i2 != 0) {
                    throw new IllegalArgumentException("Loop count must be greater than 0, or equal to GlideDrawable.LOOP_FOREVER, or equal to GlideDrawable.LOOP_INTRINSIC");
                }
                if (i2 == 0) {
                    int mo811h = gifDrawable.f8843c.f8854a.f2567a.mo811h();
                    gifDrawable.f8849j = mo811h != 0 ? mo811h : -1;
                } else {
                    gifDrawable.f8849j = i2;
                }
                gifDrawable.start();
            }
            if (C1331e.this.f1138p.isEmpty()) {
                C1331e c1331e = C1331e.this;
                c1331e.f1138p = c1331e.m339c();
            }
            resource.setBounds(C1331e.this.f1138p);
            C1331e.this.f1136n.set(resource);
            C1331e.this.f1126c.invalidate();
        }
    }

    /* renamed from: a */
    public static final void m337a(C1331e c1331e, Drawable drawable) {
        int i2 = c1331e.f1129g;
        c1331e.f1130h = i2 != -1 ? i2 != 1 ? drawable.getIntrinsicWidth() : c1331e.f1130h : c1331e.f1133k.width();
        int i3 = c1331e.f1129g;
        int intrinsicHeight = i3 != -1 ? i3 != 1 ? drawable.getIntrinsicHeight() : c1331e.f1131i : c1331e.f1133k.height();
        c1331e.f1131i = intrinsicHeight;
        int i4 = c1331e.f1130h;
        if (drawable instanceof NinePatchDrawable) {
            NinePatchDrawable ninePatchDrawable = (NinePatchDrawable) drawable;
            i4 = Math.max(i4, ninePatchDrawable.getIntrinsicWidth());
            intrinsicHeight = Math.max(intrinsicHeight, ninePatchDrawable.getIntrinsicHeight());
        }
        drawable.getBounds().set(0, 0, i4, intrinsicHeight);
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x001e, code lost:
    
        if (kotlin.jvm.internal.Intrinsics.areEqual(r0 == null ? null : java.lang.Boolean.valueOf(r0.mo1102d()), java.lang.Boolean.TRUE) != false) goto L11;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.drawable.Drawable m338b() {
        /*
            r4 = this;
            java.util.concurrent.atomic.AtomicReference<android.graphics.drawable.Drawable> r0 = r4.f1136n
            java.lang.Object r0 = r0.get()
            if (r0 != 0) goto L4e
            b.g.a.q.b r0 = r4.f1139q
            if (r0 == 0) goto L20
            if (r0 != 0) goto L10
            r0 = 0
            goto L18
        L10:
            boolean r0 = r0.mo1102d()
            java.lang.Boolean r0 = java.lang.Boolean.valueOf(r0)
        L18:
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            boolean r0 = kotlin.jvm.internal.Intrinsics.areEqual(r0, r1)
            if (r0 == 0) goto L4e
        L20:
            android.graphics.Rect r0 = r4.m339c()
            android.widget.TextView r1 = r4.f1126c
            b.g.a.i r1 = p005b.p143g.p144a.ComponentCallbacks2C1553c.m739i(r1)
            java.lang.Object r2 = r4.f1127e
            b.g.a.h r1 = r1.mo774g(r2)
            b.g.a.q.f r2 = r4.f1137o
            b.g.a.h r1 = r1.mo766a(r2)
            int r2 = r0.width()
            int r0 = r0.height()
            b.b0.a.b.e$a r3 = new b.b0.a.b.e$a
            r3.<init>(r2, r0)
            r1.m755P(r3)
            b.b0.a.b.e$a r3 = (p005b.p081b0.p082a.p084b.C1331e.a) r3
            b.g.a.q.b r0 = r3.getRequest()
            r4.f1139q = r0
        L4e:
            java.util.concurrent.atomic.AtomicReference<android.graphics.drawable.Drawable> r0 = r4.f1136n
            java.lang.Object r0 = r0.get()
            android.graphics.drawable.Drawable r0 = (android.graphics.drawable.Drawable) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p081b0.p082a.p084b.C1331e.m338b():android.graphics.drawable.Drawable");
    }

    /* renamed from: c */
    public final Rect m339c() {
        int width;
        int width2;
        int i2 = this.f1129g;
        if (i2 == -1) {
            width = this.f1133k.width();
        } else if (i2 != 1) {
            Drawable drawable = (Drawable) this.f1140r.getValue();
            Integer valueOf = drawable == null ? null : Integer.valueOf(drawable.getIntrinsicWidth());
            width = valueOf == null ? this.f1133k.width() : valueOf.intValue();
        } else {
            width = this.f1130h;
            if (width == 0) {
                width = this.f1133k.width();
            }
        }
        int i3 = this.f1129g;
        if (i3 == -1) {
            width2 = this.f1133k.width();
        } else if (i3 != 1) {
            Drawable drawable2 = (Drawable) this.f1140r.getValue();
            Integer valueOf2 = drawable2 != null ? Integer.valueOf(drawable2.getIntrinsicHeight()) : null;
            width2 = valueOf2 == null ? this.f1133k.height() : valueOf2.intValue();
        } else {
            width2 = this.f1131i;
            if (width2 == 0) {
                width2 = this.f1133k.height();
            }
        }
        return new Rect(0, 0, width, width2);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0073  */
    @Override // android.text.style.ReplacementSpan
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void draw(@org.jetbrains.annotations.NotNull android.graphics.Canvas r2, @org.jetbrains.annotations.Nullable java.lang.CharSequence r3, int r4, int r5, float r6, int r7, int r8, int r9, @org.jetbrains.annotations.NotNull android.graphics.Paint r10) {
        /*
            r1 = this;
            java.lang.String r3 = "canvas"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            java.lang.String r3 = "paint"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r3)
            android.graphics.drawable.Drawable r3 = r1.m338b()
            r2.save()
            if (r3 != 0) goto L15
            r4 = 0
            goto L19
        L15:
            android.graphics.Rect r4 = r3.getBounds()
        L19:
            if (r4 != 0) goto L1f
            android.graphics.Rect r4 = r1.m339c()
        L1f:
            java.lang.String r5 = "drawable?.bounds ?: getDrawableSize()"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            android.graphics.Paint$FontMetricsInt r5 = r10.getFontMetricsInt()
            int r9 = r1.f1135m
            r10 = 2
            if (r9 == 0) goto L56
            r0 = 1
            if (r9 == r0) goto L4a
            if (r9 == r10) goto L3e
            r4 = 3
            if (r9 == r4) goto L37
            r4 = 0
            goto L60
        L37:
            int r4 = r5.ascent
            int r5 = r5.top
            int r4 = r4 - r5
            int r4 = r4 + r7
            goto L60
        L3e:
            int r7 = r4.bottom
            int r4 = r4.height()
            int r4 = r4 + r7
            int r5 = r5.descent
            int r4 = r4 - r5
            int r4 = r4 / r10
            goto L5e
        L4a:
            int r7 = r5.descent
            int r5 = r5.ascent
            int r7 = r7 + r5
            int r4 = r4.bottom
            int r7 = r7 - r4
            int r7 = r7 / r10
            int r4 = r7 + r8
            goto L60
        L56:
            int r5 = r4.bottom
            int r4 = r4.height()
            int r4 = r4 + r5
            int r4 = r4 / r10
        L5e:
            int r4 = r8 - r4
        L60:
            android.graphics.Rect r5 = r1.f1132j
            int r7 = r5.bottom
            int r4 = r4 - r7
            int r7 = r5.top
            int r4 = r4 + r7
            int r5 = r5.left
            float r5 = (float) r5
            float r6 = r6 + r5
            float r4 = (float) r4
            r2.translate(r6, r4)
            if (r3 != 0) goto L73
            goto L76
        L73:
            r3.draw(r2)
        L76:
            r2.restore()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p081b0.p082a.p084b.C1331e.draw(android.graphics.Canvas, java.lang.CharSequence, int, int, float, int, int, int, android.graphics.Paint):void");
    }

    @Override // android.text.style.ReplacementSpan
    public int getSize(@NotNull Paint paint, @Nullable CharSequence charSequence, int i2, int i3, @Nullable Paint.FontMetricsInt fontMetricsInt) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        Paint.FontMetricsInt fontMetricsInt2 = paint.getFontMetricsInt();
        int i4 = this.f1134l;
        if (i4 > 0) {
            paint.setTextSize(i4);
        }
        Rect rect = new Rect();
        paint.getTextBounds(String.valueOf(charSequence), i2, i3, rect);
        this.f1133k.set(0, 0, rect.width() * 2, fontMetricsInt2.descent - fontMetricsInt2.ascent);
        Drawable m338b = m338b();
        Rect bounds = m338b == null ? null : m338b.getBounds();
        if (bounds == null) {
            bounds = m339c();
        }
        Intrinsics.checkNotNullExpressionValue(bounds, "drawable?.bounds ?: getDrawableSize()");
        this.f1138p = bounds;
        int height = bounds.height();
        if (fontMetricsInt != null) {
            int i5 = this.f1135m;
            if (i5 == 0) {
                int i6 = (fontMetricsInt2.bottom - height) - fontMetricsInt2.descent;
                Rect rect2 = this.f1132j;
                fontMetricsInt.ascent = (i6 - rect2.top) - rect2.bottom;
                fontMetricsInt.descent = 0;
            } else if (i5 == 1) {
                int i7 = fontMetricsInt2.descent;
                int i8 = fontMetricsInt2.ascent;
                Rect rect3 = this.f1132j;
                int i9 = (i8 - ((height - (i7 - i8)) / 2)) - rect3.top;
                fontMetricsInt.ascent = i9;
                fontMetricsInt.descent = i9 + height + rect3.bottom;
            } else if (i5 == 2) {
                int i10 = (-fontMetricsInt2.descent) - height;
                Rect rect4 = this.f1132j;
                fontMetricsInt.ascent = (i10 - rect4.top) - rect4.bottom;
                fontMetricsInt.descent = 0;
            } else if (i5 == 3) {
                int i11 = fontMetricsInt2.ascent;
                Rect rect5 = this.f1132j;
                int i12 = i11 + rect5.top;
                fontMetricsInt.ascent = i12;
                fontMetricsInt.descent = i12 + height + rect5.bottom;
            }
            fontMetricsInt.top = fontMetricsInt.ascent;
            fontMetricsInt.bottom = fontMetricsInt.descent;
        }
        int i13 = bounds.right;
        Rect rect6 = this.f1132j;
        return i13 + rect6.left + rect6.right;
    }
}
