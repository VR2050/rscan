package com.facebook.react.views.image;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.drawable.Drawable;
import kotlin.jvm.internal.DefaultConstructorMarker;
import p0.InterfaceC0645d;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class g extends s0.g implements InterfaceC0645d {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f7807f = new a(null);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    private static final class b extends Drawable {
        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            j.f(canvas, "canvas");
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -1;
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int i3) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter colorFilter) {
        }
    }

    public g() {
        super(new b());
    }

    @Override // p0.InterfaceC0645d
    public void b(String str, Object obj) {
        j.f(str, "id");
    }

    @Override // p0.InterfaceC0645d
    public void c(String str) {
        j.f(str, "id");
    }

    @Override // p0.InterfaceC0645d
    public void l(String str, Throwable th) {
        j.f(str, "id");
        j.f(th, "throwable");
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    protected boolean onLevelChange(int i3) {
        x(i3, 10000);
        return super.onLevelChange(i3);
    }

    public abstract void x(int i3, int i4);
}
