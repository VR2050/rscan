package com.facebook.react.views.text;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Layout;
import android.text.Spannable;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.ViewGroup;
import androidx.appcompat.widget.D;
import androidx.appcompat.widget.d0;
import androidx.core.view.C0252a;
import androidx.core.view.V;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.InterfaceC0454k0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import java.util.Comparator;
import p1.C0649c;
import w.AbstractC0709a;

/* JADX INFO: loaded from: classes.dex */
public class l extends D implements InterfaceC0454k0 {

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private static final ViewGroup.LayoutParams f8111v = new ViewGroup.LayoutParams(0, 0);

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f8112i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f8113j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private TextUtils.TruncateAt f8114k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f8115l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private float f8116m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private float f8117n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private float f8118o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f8119p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private boolean f8120q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f8121r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f8122s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private Q1.p f8123t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private Spannable f8124u;

    class a implements Comparator {
        a() {
        }

        @Override // java.util.Comparator
        public int compare(Object obj, Object obj2) {
            return ((WritableMap) obj).getInt("index") - ((WritableMap) obj2).getInt("index");
        }
    }

    public l(Context context) {
        super(context);
        this.f8123t = Q1.p.f2499c;
        u();
    }

    private ReactContext getReactContext() {
        Context context = getContext();
        return context instanceof d0 ? (ReactContext) ((d0) context).getBaseContext() : (ReactContext) context;
    }

    private void t() {
        if (!Float.isNaN(this.f8116m)) {
            setTextSize(0, this.f8116m);
        }
        if (Float.isNaN(this.f8118o)) {
            return;
        }
        super.setLetterSpacing(this.f8118o);
    }

    private void u() {
        this.f8113j = Integer.MAX_VALUE;
        this.f8115l = false;
        this.f8119p = 0;
        this.f8120q = false;
        this.f8121r = false;
        this.f8122s = false;
        this.f8114k = TextUtils.TruncateAt.END;
        this.f8116m = Float.NaN;
        this.f8117n = Float.NaN;
        this.f8118o = 0.0f;
        this.f8123t = Q1.p.f2499c;
        this.f8124u = null;
    }

    private static WritableMap v(int i3, int i4, int i5, int i6, int i7, int i8) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        if (i3 == 8) {
            writableMapCreateMap.putString("visibility", "gone");
            writableMapCreateMap.putInt("index", i4);
        } else if (i3 == 0) {
            writableMapCreateMap.putString("visibility", "visible");
            writableMapCreateMap.putInt("index", i4);
            writableMapCreateMap.putDouble("left", C0444f0.f(i5));
            writableMapCreateMap.putDouble("top", C0444f0.f(i6));
            writableMapCreateMap.putDouble("right", C0444f0.f(i7));
            writableMapCreateMap.putDouble("bottom", C0444f0.f(i8));
        } else {
            writableMapCreateMap.putString("visibility", "unknown");
            writableMapCreateMap.putInt("index", i4);
        }
        return writableMapCreateMap;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0454k0
    public int c(float f3, float f4) {
        int i3;
        CharSequence text = getText();
        int id = getId();
        int i4 = (int) f3;
        int i5 = (int) f4;
        Layout layout = getLayout();
        if (layout == null) {
            return id;
        }
        int lineForVertical = layout.getLineForVertical(i5);
        int lineLeft = (int) layout.getLineLeft(lineForVertical);
        int lineRight = (int) layout.getLineRight(lineForVertical);
        if ((text instanceof Spanned) && i4 >= lineLeft && i4 <= lineRight) {
            Spanned spanned = (Spanned) text;
            try {
                int offsetForHorizontal = layout.getOffsetForHorizontal(lineForVertical, i4);
                Y1.k[] kVarArr = (Y1.k[]) spanned.getSpans(offsetForHorizontal, offsetForHorizontal, Y1.k.class);
                if (kVarArr != null) {
                    int length = text.length();
                    for (int i6 = 0; i6 < kVarArr.length; i6++) {
                        int spanStart = spanned.getSpanStart(kVarArr[i6]);
                        int spanEnd = spanned.getSpanEnd(kVarArr[i6]);
                        if (spanEnd >= offsetForHorizontal && (i3 = spanEnd - spanStart) <= length) {
                            id = kVarArr[i6].a();
                            length = i3;
                        }
                    }
                }
            } catch (ArrayIndexOutOfBoundsException e3) {
                Y.a.m("ReactNative", "Crash in HorizontalMeasurementProvider: " + e3.getMessage());
            }
        }
        return id;
    }

    @Override // android.view.View
    protected boolean dispatchHoverEvent(MotionEvent motionEvent) {
        if (V.C(this)) {
            C0252a c0252aI = V.i(this);
            if (c0252aI instanceof AbstractC0709a) {
                return ((AbstractC0709a) c0252aI).v(motionEvent) || super.dispatchHoverEvent(motionEvent);
            }
        }
        return super.dispatchHoverEvent(motionEvent);
    }

    @Override // android.view.View
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        C0252a c0252aI = V.i(this);
        return (c0252aI != null && (c0252aI instanceof m) && ((m) c0252aI).w(keyEvent)) || super.dispatchKeyEvent(keyEvent);
    }

    int getGravityHorizontal() {
        return getGravity() & 8388615;
    }

    public Spannable getSpanned() {
        return this.f8124u;
    }

    @Override // android.widget.TextView, android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    @Override // android.widget.TextView, android.view.View, android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable drawable) {
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                if (pVar.a() == drawable) {
                    invalidate();
                }
            }
        }
        super.invalidateDrawable(drawable);
    }

    @Override // android.widget.TextView, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        setTextIsSelectable(this.f8121r);
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                pVar.c();
            }
        }
    }

    @Override // androidx.appcompat.widget.D, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                pVar.d();
            }
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        C0649c c0649c = new C0649c("ReactTextView.onDraw");
        try {
            if (this.f8115l && getSpanned() != null && this.f8122s) {
                this.f8122s = false;
                Spannable spanned = getSpanned();
                float width = getWidth();
                com.facebook.yoga.p pVar = com.facebook.yoga.p.EXACTLY;
                s.a(spanned, width, pVar, getHeight(), pVar, this.f8117n, this.f8113j, getIncludeFontPadding(), getBreakStrategy(), getHyphenationFrequency(), Layout.Alignment.ALIGN_NORMAL, Build.VERSION.SDK_INT < 26 ? -1 : getJustificationMode(), getPaint());
                setText(getSpanned());
            }
            if (this.f8123t != Q1.p.f2499c) {
                C0433a.a(this, canvas);
            }
            super.onDraw(canvas);
            c0649c.close();
        } finally {
        }
    }

    @Override // android.view.View
    public void onFinishTemporaryDetach() {
        super.onFinishTemporaryDetach();
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                pVar.e();
            }
        }
    }

    @Override // android.widget.TextView, android.view.View
    public final void onFocusChanged(boolean z3, int i3, Rect rect) {
        super.onFocusChanged(z3, i3, rect);
        C0252a c0252aI = V.i(this);
        if (c0252aI == null || !(c0252aI instanceof m)) {
            return;
        }
        ((m) c0252aI).G(z3, i3, rect);
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0122 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0137  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x015f A[SYNTHETIC] */
    @Override // androidx.appcompat.widget.D, android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onLayout(boolean r24, int r25, int r26, int r27, int r28) {
        /*
            Method dump skipped, instruction units count: 421
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.text.l.onLayout(boolean, int, int, int, int):void");
    }

    @Override // androidx.appcompat.widget.D, android.widget.TextView, android.view.View
    protected void onMeasure(int i3, int i4) {
        C0649c c0649c = new C0649c("ReactTextView.onMeasure");
        try {
            super.onMeasure(i3, i4);
            c0649c.close();
        } catch (Throwable th) {
            try {
                c0649c.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    @Override // android.view.View
    public void onStartTemporaryDetach() {
        super.onStartTemporaryDetach();
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                pVar.f();
            }
        }
    }

    public void setAdjustFontSizeToFit(boolean z3) {
        this.f8115l = z3;
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        C0433a.n(this, Integer.valueOf(i3));
    }

    public void setBorderRadius(float f3) {
        x(f3, Q1.d.f2402b.ordinal());
    }

    public void setBorderStyle(String str) {
        C0433a.r(this, str == null ? null : Q1.f.b(str));
    }

    @Override // android.widget.TextView
    public void setBreakStrategy(int i3) {
        super.setBreakStrategy(i3);
        this.f8122s = true;
    }

    public void setEllipsizeLocation(TextUtils.TruncateAt truncateAt) {
        this.f8114k = truncateAt;
    }

    public void setFontSize(float f3) {
        this.f8116m = (float) (this.f8115l ? Math.ceil(C0444f0.j(f3)) : Math.ceil(C0444f0.h(f3)));
        t();
    }

    void setGravityHorizontal(int i3) {
        if (i3 == 0) {
            i3 = 8388611;
        }
        setGravity(i3 | (getGravity() & (-8388616)));
    }

    void setGravityVertical(int i3) {
        if (i3 == 0) {
            i3 = 48;
        }
        setGravity(i3 | (getGravity() & (-113)));
    }

    @Override // android.widget.TextView
    public void setHyphenationFrequency(int i3) {
        super.setHyphenationFrequency(i3);
        this.f8122s = true;
    }

    @Override // android.widget.TextView
    public void setIncludeFontPadding(boolean z3) {
        super.setIncludeFontPadding(z3);
        this.f8122s = true;
    }

    @Override // android.widget.TextView
    public void setLetterSpacing(float f3) {
        if (Float.isNaN(f3)) {
            return;
        }
        this.f8118o = C0444f0.h(f3) / this.f8116m;
        t();
    }

    public void setLinkifyMask(int i3) {
        this.f8119p = i3;
    }

    public void setMinimumFontSize(float f3) {
        this.f8117n = f3;
        this.f8122s = true;
    }

    public void setNotifyOnInlineViewLayout(boolean z3) {
        this.f8120q = z3;
    }

    public void setNumberOfLines(int i3) {
        if (i3 == 0) {
            i3 = Integer.MAX_VALUE;
        }
        this.f8113j = i3;
        setMaxLines(i3);
        this.f8122s = true;
    }

    public void setOverflow(String str) {
        if (str == null) {
            this.f8123t = Q1.p.f2499c;
        } else {
            Q1.p pVarB = Q1.p.b(str);
            if (pVarB == null) {
                pVarB = Q1.p.f2499c;
            }
            this.f8123t = pVarB;
        }
        invalidate();
    }

    public void setSpanned(Spannable spannable) {
        this.f8124u = spannable;
        this.f8122s = true;
    }

    public void setText(h hVar) {
        C0649c c0649c = new C0649c("ReactTextView.setText(ReactTextUpdate)");
        try {
            this.f8112i = hVar.b();
            if (getLayoutParams() == null) {
                setLayoutParams(f8111v);
            }
            Spannable spannableI = hVar.i();
            int i3 = this.f8119p;
            if (i3 > 0) {
                Linkify.addLinks(spannableI, i3);
                setMovementMethod(LinkMovementMethod.getInstance());
            }
            setText(spannableI);
            float f3 = hVar.f();
            float fH = hVar.h();
            float fG = hVar.g();
            float fE = hVar.e();
            if (f3 != -1.0f && fH != -1.0f && fG != -1.0f && fE != -1.0f) {
                setPadding((int) Math.floor(f3), (int) Math.floor(fH), (int) Math.floor(fG), (int) Math.floor(fE));
            }
            int iJ = hVar.j();
            if (iJ != getGravityHorizontal()) {
                setGravityHorizontal(iJ);
            }
            if (getBreakStrategy() != hVar.k()) {
                setBreakStrategy(hVar.k());
            }
            if (Build.VERSION.SDK_INT >= 26 && getJustificationMode() != hVar.d()) {
                setJustificationMode(hVar.d());
            }
            requestLayout();
            c0649c.close();
        } catch (Throwable th) {
            try {
                c0649c.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    @Override // android.widget.TextView
    public void setTextIsSelectable(boolean z3) {
        this.f8121r = z3;
        super.setTextIsSelectable(z3);
    }

    @Override // android.widget.TextView, android.view.View
    protected boolean verifyDrawable(Drawable drawable) {
        if (this.f8112i && (getText() instanceof Spanned)) {
            Spanned spanned = (Spanned) getText();
            for (Y1.p pVar : (Y1.p[]) spanned.getSpans(0, spanned.length(), Y1.p.class)) {
                if (pVar.a() == drawable) {
                    return true;
                }
            }
        }
        return super.verifyDrawable(drawable);
    }

    void w() {
        u();
        C0433a.m(this);
        setBreakStrategy(0);
        setMovementMethod(getDefaultMovementMethod());
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 26) {
            setJustificationMode(0);
        }
        setLayoutParams(f8111v);
        super.setText((CharSequence) null);
        t();
        setGravity(8388659);
        setNumberOfLines(this.f8113j);
        setAdjustFontSizeToFit(this.f8115l);
        setLinkifyMask(this.f8119p);
        setTextIsSelectable(this.f8121r);
        setIncludeFontPadding(true);
        setEnabled(true);
        setLinkifyMask(0);
        setEllipsizeLocation(this.f8114k);
        setEnabled(true);
        if (i3 >= 26) {
            setFocusable(16);
        }
        setHyphenationFrequency(0);
        y();
    }

    public void x(float f3, int i3) {
        C0433a.q(this, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(C0444f0.f(f3), X.f7535b));
    }

    public void y() {
        setEllipsize((this.f8113j == Integer.MAX_VALUE || this.f8115l) ? null : this.f8114k);
    }
}
