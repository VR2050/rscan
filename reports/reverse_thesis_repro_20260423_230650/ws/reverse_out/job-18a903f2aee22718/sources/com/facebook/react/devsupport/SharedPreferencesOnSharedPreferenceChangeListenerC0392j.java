package com.facebook.react.devsupport;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import f1.C0527a;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.react.devsupport.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class SharedPreferencesOnSharedPreferenceChangeListenerC0392j implements B1.a, SharedPreferences.OnSharedPreferenceChangeListener {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f6858e = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final b f6859a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final SharedPreferences f6860b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final G1.d f6861c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f6862d;

    /* JADX INFO: renamed from: com.facebook.react.devsupport.j$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.j$b */
    public interface b {
        void a();
    }

    public SharedPreferencesOnSharedPreferenceChangeListenerC0392j(Context context, b bVar) {
        t2.j.f(context, "applicationContext");
        this.f6859a = bVar;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        t2.j.e(defaultSharedPreferences, "getDefaultSharedPreferences(...)");
        this.f6860b = defaultSharedPreferences;
        this.f6861c = new G1.d(context);
        defaultSharedPreferences.registerOnSharedPreferenceChangeListener(this);
        this.f6862d = C0527a.f9198b;
    }

    @Override // B1.a
    public void c(boolean z3) {
        this.f6860b.edit().putBoolean("fps_debug", z3).apply();
    }

    @Override // B1.a
    public void e(boolean z3) {
        this.f6860b.edit().putBoolean("hot_module_replacement", z3).apply();
    }

    @Override // B1.a
    public boolean f() {
        return this.f6860b.getBoolean("inspector_debug", false);
    }

    @Override // B1.a
    public G1.d g() {
        return this.f6861c;
    }

    @Override // B1.a
    public void h(boolean z3) {
        this.f6860b.edit().putBoolean("inspector_debug", z3).apply();
    }

    @Override // B1.a
    public boolean i() {
        return this.f6862d;
    }

    @Override // B1.a
    public void j(boolean z3) {
        this.f6860b.edit().putBoolean("js_dev_mode_debug", z3).apply();
    }

    @Override // B1.a
    public boolean k() {
        return this.f6860b.getBoolean("js_minify_debug", false);
    }

    @Override // B1.a
    public boolean l() {
        return this.f6860b.getBoolean("fps_debug", false);
    }

    @Override // B1.a
    public boolean m() {
        return this.f6860b.getBoolean("js_dev_mode_debug", true);
    }

    @Override // B1.a
    public boolean n() {
        return this.f6860b.getBoolean("hot_module_replacement", true);
    }

    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) {
        t2.j.f(sharedPreferences, "sharedPreferences");
        if (this.f6859a != null) {
            if (t2.j.b("fps_debug", str) || t2.j.b("js_dev_mode_debug", str) || t2.j.b("js_minify_debug", str)) {
                this.f6859a.a();
            }
        }
    }
}
