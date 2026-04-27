package com.facebook.react.views.progressbar;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ProgressBar;
import com.facebook.react.uimanager.U;
import com.facebook.react.views.progressbar.ReactProgressBarViewManager;
import com.facebook.yoga.o;
import com.facebook.yoga.p;
import com.facebook.yoga.q;
import com.facebook.yoga.r;
import java.util.HashSet;
import java.util.Set;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b extends U implements o {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final SparseIntArray f7870A = new SparseIntArray();

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final SparseIntArray f7871B = new SparseIntArray();

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final Set f7872C = new HashSet();

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private String f7873D;

    public b() {
        Y0(this);
        this.f7873D = ReactProgressBarViewManager.DEFAULT_STYLE;
    }

    @Override // com.facebook.yoga.o
    public long K(r rVar, float f3, p pVar, float f4, p pVar2) {
        j.f(rVar, "node");
        j.f(pVar, "widthMode");
        j.f(pVar2, "heightMode");
        ReactProgressBarViewManager.a aVar = ReactProgressBarViewManager.Companion;
        int iB = aVar.b(this.f7873D);
        if (!this.f7872C.contains(Integer.valueOf(iB))) {
            ProgressBar progressBarA = aVar.a(l(), iB);
            int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(-2, 0);
            progressBarA.measure(iMakeMeasureSpec, iMakeMeasureSpec);
            this.f7870A.put(iB, progressBarA.getMeasuredHeight());
            this.f7871B.put(iB, progressBarA.getMeasuredWidth());
            this.f7872C.add(Integer.valueOf(iB));
        }
        return q.b(this.f7871B.get(iB), this.f7870A.get(iB));
    }

    @K1.a(name = ReactProgressBarViewManager.PROP_STYLE)
    public final void setStyle(String str) {
        if (str == null) {
            str = ReactProgressBarViewManager.DEFAULT_STYLE;
        }
        this.f7873D = str;
    }
}
