package com.facebook.react.views.image;

import android.graphics.Matrix;
import android.graphics.Rect;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s0.p;
import s0.q;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class i extends p {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final a f7835l = new a(null);

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final q f7836m = new i();

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final q a() {
            return i.f7836m;
        }

        private a() {
        }
    }

    @Override // s0.p
    public void b(Matrix matrix, Rect rect, int i3, int i4, float f3, float f4, float f5, float f6) {
        j.f(matrix, "outTransform");
        j.f(rect, "parentRect");
        float fD = w2.d.d(Math.min(f5, f6), 1.0f);
        float f7 = rect.left;
        float f8 = rect.top;
        matrix.setScale(fD, fD);
        matrix.postTranslate(Math.round(f7), Math.round(f8));
    }

    public String toString() {
        return "start_inside";
    }
}
