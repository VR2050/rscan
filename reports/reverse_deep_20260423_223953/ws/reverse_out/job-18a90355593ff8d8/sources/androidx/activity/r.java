package androidx.activity;

import android.view.View;

/* JADX INFO: loaded from: classes.dex */
public abstract class r {
    public static final void a(View view, o oVar) {
        t2.j.f(view, "<this>");
        t2.j.f(oVar, "onBackPressedDispatcherOwner");
        view.setTag(p.f3002b, oVar);
    }
}
