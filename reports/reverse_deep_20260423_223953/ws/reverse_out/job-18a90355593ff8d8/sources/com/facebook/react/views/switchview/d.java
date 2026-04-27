package com.facebook.react.views.switchview;

import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.U;
import com.facebook.yoga.o;
import com.facebook.yoga.p;
import com.facebook.yoga.q;
import com.facebook.yoga.r;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends U implements o {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private int f8041A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private int f8042B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private boolean f8043C;

    public d() {
        w1();
    }

    private final void w1() {
        Y0(this);
    }

    @Override // com.facebook.yoga.o
    public long K(r rVar, float f3, p pVar, float f4, p pVar2) {
        j.f(rVar, "node");
        j.f(pVar, "widthMode");
        j.f(pVar2, "heightMode");
        if (!this.f8043C) {
            B0 b0L = l();
            j.e(b0L, "getThemedContext(...)");
            a aVar = new a(b0L);
            aVar.setShowText(false);
            int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
            aVar.measure(iMakeMeasureSpec, iMakeMeasureSpec);
            this.f8041A = aVar.getMeasuredWidth();
            this.f8042B = aVar.getMeasuredHeight();
            this.f8043C = true;
        }
        return q.b(this.f8041A, this.f8042B);
    }
}
