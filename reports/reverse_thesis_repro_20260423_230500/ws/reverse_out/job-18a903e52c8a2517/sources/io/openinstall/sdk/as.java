package io.openinstall.sdk;

import android.app.Activity;
import android.content.ClipData;
import android.content.Context;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes3.dex */
public class as {
    private static final as a = new as();
    private Context c;
    private WeakReference<Activity> d;
    private String e;
    private String f;
    private Boolean g;
    private Boolean h;
    private Boolean m;
    private ClipData n;
    private bd o;
    private boolean b = false;
    private boolean i = false;
    private boolean j = false;
    private boolean k = false;
    private boolean l = false;
    private boolean p = false;
    private boolean q = false;
    private boolean r = false;

    private as() {
    }

    public static as a() {
        return a;
    }

    public void a(Activity activity) {
        if (activity == null) {
            this.d = null;
        } else {
            this.d = new WeakReference<>(activity);
        }
    }

    public void a(ClipData clipData) {
        this.n = clipData;
    }

    public void a(Context context) {
        this.c = context.getApplicationContext();
    }

    public void a(bd bdVar) {
        this.o = bdVar;
    }

    public void a(Boolean bool) {
        this.m = bool;
    }

    public void a(String str) {
        this.e = str;
    }

    public void a(boolean z) {
        this.p = z;
    }

    public void b(Boolean bool) {
        this.g = bool;
    }

    public void b(String str) {
        this.f = str;
    }

    public void b(boolean z) {
        this.q = z;
    }

    public boolean b() {
        return this.b;
    }

    public Context c() {
        return this.c;
    }

    public void c(boolean z) {
        this.r = z;
    }

    public Activity d() {
        WeakReference<Activity> weakReference = this.d;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    public String e() {
        return this.e;
    }

    public String f() {
        return this.f;
    }

    public Boolean g() {
        if (this.m == null) {
            this.m = Boolean.valueOf(ea.b(this.c));
        }
        return this.m;
    }

    public ClipData h() {
        return this.n;
    }

    public Boolean i() {
        Boolean bool = this.g;
        if (bool == null) {
            return true;
        }
        return bool;
    }

    public Boolean j() {
        if (this.h == null) {
            this.h = Boolean.valueOf(ea.c(this.c));
        }
        return this.h;
    }

    public bd k() {
        return this.o;
    }

    public boolean l() {
        return this.p;
    }

    public boolean m() {
        return this.q;
    }

    public boolean n() {
        return this.r;
    }
}
