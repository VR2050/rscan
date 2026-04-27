package com.facebook.react.views.text;

import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Bundle;
import android.text.Layout;
import android.text.Spannable;
import android.text.Spanned;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ClickableSpan;
import android.view.View;
import android.widget.TextView;
import androidx.core.view.V;
import c1.AbstractC0339k;
import c1.AbstractC0342n;
import com.facebook.react.uimanager.C0448h0;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import r.v;
import r.w;

/* JADX INFO: loaded from: classes.dex */
public final class m extends C0448h0 {

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    public static final b f8126y = new b(null);

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private a f8127x;

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f8128a;

        /* JADX INFO: renamed from: com.facebook.react.views.text.m$a$a, reason: collision with other inner class name */
        public static final class C0121a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private String f8129a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            private int f8130b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            private int f8131c;

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            private int f8132d;

            public final String a() {
                return this.f8129a;
            }

            public final int b() {
                return this.f8131c;
            }

            public final int c() {
                return this.f8132d;
            }

            public final int d() {
                return this.f8130b;
            }

            public final void e(String str) {
                this.f8129a = str;
            }

            public final void f(int i3) {
                this.f8131c = i3;
            }

            public final void g(int i3) {
                this.f8132d = i3;
            }

            public final void h(int i3) {
                this.f8130b = i3;
            }
        }

        public a(ClickableSpan[] clickableSpanArr, Spannable spannable) {
            t2.j.f(clickableSpanArr, "spans");
            t2.j.f(spannable, "text");
            ArrayList arrayList = new ArrayList();
            int length = clickableSpanArr.length;
            for (int i3 = 0; i3 < length; i3++) {
                ClickableSpan clickableSpan = clickableSpanArr[i3];
                int spanStart = spannable.getSpanStart(clickableSpan);
                int spanEnd = spannable.getSpanEnd(clickableSpan);
                if (spanStart != spanEnd && spanStart >= 0 && spanEnd >= 0 && spanStart <= spannable.length() && spanEnd <= spannable.length()) {
                    C0121a c0121a = new C0121a();
                    c0121a.e(spannable.subSequence(spanStart, spanEnd).toString());
                    c0121a.h(spanStart);
                    c0121a.f(spanEnd);
                    c0121a.g((clickableSpanArr.length - 1) - i3);
                    arrayList.add(c0121a);
                }
            }
            this.f8128a = arrayList;
        }

        public final C0121a a(int i3) {
            for (C0121a c0121a : this.f8128a) {
                if (c0121a.c() == i3) {
                    return c0121a;
                }
            }
            return null;
        }

        public final C0121a b(int i3, int i4) {
            for (C0121a c0121a : this.f8128a) {
                if (c0121a.d() == i3 && c0121a.b() == i4) {
                    return c0121a;
                }
            }
            return null;
        }

        public final int c() {
            return this.f8128a.size();
        }
    }

    public static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void a(View view, boolean z3, int i3) {
            t2.j.f(view, "view");
            V.X(view, new m(view, z3, i3));
        }

        public final void b(View view, boolean z3, int i3) {
            t2.j.f(view, "view");
            if (V.C(view)) {
                return;
            }
            if (view.getTag(AbstractC0339k.f5583g) == null && view.getTag(AbstractC0339k.f5584h) == null && view.getTag(AbstractC0339k.f5577a) == null && view.getTag(AbstractC0339k.f5596t) == null && view.getTag(AbstractC0339k.f5579c) == null && view.getTag(AbstractC0339k.f5582f) == null && view.getTag(AbstractC0339k.f5602z) == null) {
                return;
            }
            V.X(view, new m(view, z3, i3));
        }

        private b() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(View view, boolean z3, int i3) {
        super(view, z3, i3);
        t2.j.f(view, "view");
        this.f8127x = (a) V().getTag(AbstractC0339k.f5582f);
    }

    private final Rect k0(a.C0121a c0121a) {
        if (!(V() instanceof TextView)) {
            return new Rect(0, 0, V().getWidth(), V().getHeight());
        }
        View viewV = V();
        t2.j.d(viewV, "null cannot be cast to non-null type android.widget.TextView");
        TextView textView = (TextView) viewV;
        Layout layout = textView.getLayout();
        if (layout == null) {
            return new Rect(0, 0, textView.getWidth(), textView.getHeight());
        }
        int iD = c0121a.d();
        int iB = c0121a.b();
        int lineForOffset = layout.getLineForOffset(iD);
        if (iD > layout.getLineEnd(lineForOffset)) {
            return null;
        }
        Rect rect = new Rect();
        double primaryHorizontal = layout.getPrimaryHorizontal(iD);
        new Paint().setTextSize(((AbsoluteSizeSpan) l0(c0121a.d(), c0121a.b(), AbsoluteSizeSpan.class)) != null ? r9.getSize() : textView.getTextSize());
        int iCeil = (int) Math.ceil(r3.measureText(c0121a.a()));
        boolean z3 = lineForOffset != layout.getLineForOffset(iB);
        layout.getLineBounds(lineForOffset, rect);
        int scrollY = textView.getScrollY() + textView.getTotalPaddingTop();
        rect.top += scrollY;
        rect.bottom += scrollY;
        rect.left = (int) (((double) rect.left) + ((primaryHorizontal + ((double) textView.getTotalPaddingLeft())) - ((double) textView.getScrollX())));
        if (z3) {
            return new Rect(rect.left, rect.top, rect.right, rect.bottom);
        }
        int i3 = rect.left;
        return new Rect(i3, rect.top, iCeil + i3, rect.bottom);
    }

    @Override // com.facebook.react.uimanager.C0448h0, w.AbstractC0709a
    protected void A(List list) {
        t2.j.f(list, "virtualViewIds");
        a aVar = this.f8127x;
        if (aVar == null) {
            return;
        }
        int iC = aVar.c();
        for (int i3 = 0; i3 < iC; i3++) {
            list.add(Integer.valueOf(i3));
        }
    }

    @Override // com.facebook.react.uimanager.C0448h0, w.AbstractC0709a
    protected boolean H(int i3, int i4, Bundle bundle) {
        a.C0121a c0121aA;
        ClickableSpan clickableSpan;
        a aVar = this.f8127x;
        if (aVar == null || aVar == null || (c0121aA = aVar.a(i3)) == null || (clickableSpan = (ClickableSpan) l0(c0121aA.d(), c0121aA.b(), ClickableSpan.class)) == null || !(clickableSpan instanceof Y1.f) || i4 != 16) {
            return false;
        }
        View viewV = V();
        t2.j.e(viewV, "getHostView(...)");
        ((Y1.f) clickableSpan).onClick(viewV);
        return true;
    }

    @Override // com.facebook.react.uimanager.C0448h0, w.AbstractC0709a
    protected void L(int i3, v vVar) {
        t2.j.f(vVar, "node");
        a aVar = this.f8127x;
        if (aVar == null) {
            vVar.t0("");
            vVar.l0(new Rect(0, 0, 1, 1));
            return;
        }
        a.C0121a c0121aA = aVar.a(i3);
        if (c0121aA == null) {
            vVar.t0("");
            vVar.l0(new Rect(0, 0, 1, 1));
            return;
        }
        Rect rectK0 = k0(c0121aA);
        if (rectK0 == null) {
            vVar.t0("");
            vVar.l0(new Rect(0, 0, 1, 1));
            return;
        }
        vVar.t0(c0121aA.a());
        vVar.a(16);
        vVar.l0(rectK0);
        vVar.F0(V().getResources().getString(AbstractC0342n.f5643v));
        vVar.p0(C0448h0.d.e(C0448h0.d.BUTTON));
    }

    @Override // w.AbstractC0709a
    protected void M(int i3, boolean z3) {
        a.C0121a c0121aA;
        ClickableSpan clickableSpan;
        a aVar = this.f8127x;
        if (aVar == null || aVar == null || (c0121aA = aVar.a(i3)) == null || (clickableSpan = (ClickableSpan) l0(c0121aA.d(), c0121aA.b(), ClickableSpan.class)) == null || !(clickableSpan instanceof Y1.f) || !(V() instanceof l)) {
            return;
        }
        Y1.f fVar = (Y1.f) clickableSpan;
        fVar.b(z3);
        View viewV = V();
        t2.j.d(viewV, "null cannot be cast to non-null type android.widget.TextView");
        fVar.a(((TextView) viewV).getHighlightColor());
        V().invalidate();
    }

    @Override // com.facebook.react.uimanager.C0448h0, w.AbstractC0709a, androidx.core.view.C0252a
    public w b(View view) {
        t2.j.f(view, "host");
        if (this.f8127x != null) {
            return j0(view);
        }
        return null;
    }

    protected final Object l0(int i3, int i4, Class cls) {
        if (!(V() instanceof TextView)) {
            return null;
        }
        View viewV = V();
        t2.j.d(viewV, "null cannot be cast to non-null type android.widget.TextView");
        if (!(((TextView) viewV).getText() instanceof Spanned)) {
            return null;
        }
        View viewV2 = V();
        t2.j.d(viewV2, "null cannot be cast to non-null type android.widget.TextView");
        CharSequence text = ((TextView) viewV2).getText();
        t2.j.d(text, "null cannot be cast to non-null type android.text.Spanned");
        Object[] spans = ((Spanned) text).getSpans(i3, i4, cls);
        t2.j.c(spans);
        if (spans.length == 0) {
            return null;
        }
        return spans[0];
    }

    @Override // com.facebook.react.uimanager.C0448h0, w.AbstractC0709a
    protected int z(float f3, float f4) {
        Layout layout;
        a aVar = this.f8127x;
        if (aVar == null || aVar.c() == 0 || !(V() instanceof TextView)) {
            return Integer.MIN_VALUE;
        }
        View viewV = V();
        t2.j.d(viewV, "null cannot be cast to non-null type android.widget.TextView");
        TextView textView = (TextView) viewV;
        if (!(textView.getText() instanceof Spanned) || (layout = textView.getLayout()) == null) {
            return Integer.MIN_VALUE;
        }
        int offsetForHorizontal = layout.getOffsetForHorizontal(layout.getLineForVertical((int) ((f4 - textView.getTotalPaddingTop()) + textView.getScrollY())), (f3 - textView.getTotalPaddingLeft()) + textView.getScrollX());
        ClickableSpan clickableSpan = (ClickableSpan) l0(offsetForHorizontal, offsetForHorizontal, ClickableSpan.class);
        if (clickableSpan == null) {
            return Integer.MIN_VALUE;
        }
        CharSequence text = textView.getText();
        t2.j.d(text, "null cannot be cast to non-null type android.text.Spanned");
        Spanned spanned = (Spanned) text;
        a.C0121a c0121aB = aVar.b(spanned.getSpanStart(clickableSpan), spanned.getSpanEnd(clickableSpan));
        if (c0121aB != null) {
            return c0121aB.c();
        }
        return Integer.MIN_VALUE;
    }
}
