package io.openinstall.sdk;

import android.content.SharedPreferences;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/* JADX INFO: loaded from: classes3.dex */
public class at {
    private Future<SharedPreferences> a;
    private final String b = "";

    public at(Future<SharedPreferences> future) {
        this.a = future;
    }

    private void a(String str, int i) {
        try {
            SharedPreferences.Editor editorEdit = this.a.get().edit();
            editorEdit.putInt(str, i);
            editorEdit.apply();
        } catch (InterruptedException e) {
        } catch (ExecutionException e2) {
        }
    }

    private void a(String str, long j) {
        try {
            SharedPreferences.Editor editorEdit = this.a.get().edit();
            editorEdit.putLong(str, j);
            editorEdit.apply();
        } catch (InterruptedException e) {
        } catch (ExecutionException e2) {
        }
    }

    private void a(String str, String str2) {
        try {
            SharedPreferences.Editor editorEdit = this.a.get().edit();
            editorEdit.putString(str, str2);
            editorEdit.apply();
        } catch (InterruptedException e) {
        } catch (ExecutionException e2) {
        }
    }

    private void a(String str, boolean z) {
        try {
            SharedPreferences.Editor editorEdit = this.a.get().edit();
            editorEdit.putBoolean(str, z);
            editorEdit.apply();
        } catch (InterruptedException e) {
        } catch (ExecutionException e2) {
        }
    }

    private int b(String str, int i) {
        try {
            return this.a.get().getInt(str, i);
        } catch (InterruptedException | ExecutionException e) {
            return i;
        }
    }

    private long b(String str, long j) {
        try {
            return this.a.get().getLong(str, j);
        } catch (InterruptedException | ExecutionException e) {
            return j;
        }
    }

    private String b(String str, String str2) {
        try {
            return this.a.get().getString(str, str2);
        } catch (InterruptedException | ExecutionException e) {
            return str2;
        }
    }

    private boolean b(String str, boolean z) {
        try {
            return this.a.get().getBoolean(str, z);
        } catch (InterruptedException | ExecutionException e) {
            return z;
        }
    }

    public ar a(String str) {
        return ar.a(b(str, ar.a.a()));
    }

    public String a() {
        return b("FM_init_data", "");
    }

    public void a(long j) {
        a("FM_last_time", j);
    }

    public void a(aw awVar) {
        a("FM_config_data", awVar.i());
    }

    public void a(by byVar) {
        a("FM_pb_data", byVar == null ? "" : byVar.d());
    }

    public void a(String str, ar arVar) {
        a(str, arVar.a());
    }

    public void a(boolean z) {
        a("FM_dynamic_fetch", z);
    }

    public String b() {
        return b("FM_init_msg", "");
    }

    public void b(String str) {
        a("FM_init_data", str);
    }

    public void b(boolean z) {
        a("FM_should_show_index", z);
    }

    public aw c() {
        return aw.b(b("FM_config_data", ""));
    }

    public void c(String str) {
        a("FM_init_msg", str);
    }

    public void c(boolean z) {
        a("FM_request_forbid", z);
    }

    public long d() {
        return b("FM_last_time", 0L);
    }

    public void d(String str) {
        a("FM_android_id", str);
    }

    public by e() {
        return by.c(b("FM_pb_data", ""));
    }

    public void e(String str) {
        a("FM_serial_number", str);
    }

    public String f() {
        return b("FM_android_id", (String) null);
    }

    public String g() {
        return b("FM_serial_number", (String) null);
    }

    public boolean h() {
        return b("FM_dynamic_fetch", true);
    }

    public boolean i() {
        return b("FM_should_show_index", false);
    }

    public boolean j() {
        return b("FM_request_forbid", false);
    }

    public void k() {
        try {
            SharedPreferences.Editor editorEdit = this.a.get().edit();
            editorEdit.clear();
            editorEdit.apply();
        } catch (InterruptedException e) {
        } catch (ExecutionException e2) {
        }
    }
}
