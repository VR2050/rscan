package com.facebook.react.views.text;

import android.text.Spannable;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final a f8100k = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Spannable f8101a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f8102b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f8103c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f8104d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final float f8105e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final float f8106f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final float f8107g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f8108h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f8109i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int f8110j;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final h a(Spannable spannable, int i3, int i4, int i5, int i6) {
            t2.j.f(spannable, "text");
            return new h(spannable, i3, false, i4, i5, i6);
        }

        private a() {
        }
    }

    public h(Spannable spannable, int i3, boolean z3, float f3, float f4, float f5, float f6, int i4, int i5, int i6) {
        t2.j.f(spannable, "text");
        this.f8101a = spannable;
        this.f8102b = i3;
        this.f8103c = z3;
        this.f8104d = f3;
        this.f8105e = f4;
        this.f8106f = f5;
        this.f8107g = f6;
        this.f8108h = i4;
        this.f8109i = i5;
        this.f8110j = i6;
    }

    public static final h a(Spannable spannable, int i3, int i4, int i5, int i6) {
        return f8100k.a(spannable, i3, i4, i5, i6);
    }

    public final boolean b() {
        return this.f8103c;
    }

    public final int c() {
        return this.f8102b;
    }

    public final int d() {
        return this.f8110j;
    }

    public final float e() {
        return this.f8107g;
    }

    public final float f() {
        return this.f8104d;
    }

    public final float g() {
        return this.f8106f;
    }

    public final float h() {
        return this.f8105e;
    }

    public final Spannable i() {
        return this.f8101a;
    }

    public final int j() {
        return this.f8108h;
    }

    public final int k() {
        return this.f8109i;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public h(Spannable spannable, int i3, boolean z3, int i4, int i5, int i6) {
        this(spannable, i3, z3, -1.0f, -1.0f, -1.0f, -1.0f, i4, i5, i6);
        t2.j.f(spannable, "text");
    }
}
