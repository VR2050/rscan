package com.facebook.react.devsupport;

import android.content.Context;
import com.facebook.react.devsupport.SharedPreferencesOnSharedPreferenceChangeListenerC0392j;

/* JADX INFO: loaded from: classes.dex */
public final class b0 extends k0 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final B1.a f6813b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0393k f6814c;

    public static final class a implements SharedPreferencesOnSharedPreferenceChangeListenerC0392j.b {
        a() {
        }

        @Override // com.facebook.react.devsupport.SharedPreferencesOnSharedPreferenceChangeListenerC0392j.b
        public void a() {
        }
    }

    public b0(Context context) {
        t2.j.f(context, "applicationContext");
        this.f6813b = new SharedPreferencesOnSharedPreferenceChangeListenerC0392j(context, new a());
        this.f6814c = new C0393k(n(), context, n().g());
    }

    @Override // com.facebook.react.devsupport.k0, j1.e
    public void l() {
        this.f6814c.i();
    }

    @Override // com.facebook.react.devsupport.k0, j1.e
    public B1.a n() {
        return this.f6813b;
    }

    @Override // com.facebook.react.devsupport.k0, j1.e
    public void t() {
        this.f6814c.y();
    }
}
