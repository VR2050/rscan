package androidx.core.app;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import androidx.core.view.AbstractC0282t;
import androidx.lifecycle.f;
import androidx.lifecycle.t;
import l.C0612g;

/* JADX INFO: loaded from: classes.dex */
public abstract class f extends Activity implements androidx.lifecycle.k, AbstractC0282t.a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0612g f4245b = new C0612g();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final androidx.lifecycle.l f4246c = new androidx.lifecycle.l(this);

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    private final boolean y(String[] strArr) {
        if (strArr == null || strArr.length == 0) {
            return false;
        }
        String str = strArr[0];
        switch (str.hashCode()) {
            case -645125871:
                return str.equals("--translation") && Build.VERSION.SDK_INT >= 31;
            case 100470631:
                if (!str.equals("--dump-dumpable")) {
                    return false;
                }
                break;
            case 472614934:
                if (!str.equals("--list-dumpables")) {
                    return false;
                }
                break;
            case 1159329357:
                return str.equals("--contentcapture") && Build.VERSION.SDK_INT >= 29;
            case 1455016274:
                return str.equals("--autofill") && Build.VERSION.SDK_INT >= 26;
            default:
                return false;
        }
        return Build.VERSION.SDK_INT >= 33;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        t2.j.f(keyEvent, "event");
        View decorView = getWindow().getDecorView();
        t2.j.e(decorView, "window.decorView");
        if (AbstractC0282t.d(decorView, keyEvent)) {
            return true;
        }
        return AbstractC0282t.e(this, decorView, this, keyEvent);
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean dispatchKeyShortcutEvent(KeyEvent keyEvent) {
        t2.j.f(keyEvent, "event");
        View decorView = getWindow().getDecorView();
        t2.j.e(decorView, "window.decorView");
        if (AbstractC0282t.d(decorView, keyEvent)) {
            return true;
        }
        return super.dispatchKeyShortcutEvent(keyEvent);
    }

    @Override // androidx.core.view.AbstractC0282t.a
    public boolean e(KeyEvent keyEvent) {
        t2.j.f(keyEvent, "event");
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        t.f5171c.c(this);
    }

    @Override // android.app.Activity
    protected void onSaveInstanceState(Bundle bundle) {
        t2.j.f(bundle, "outState");
        this.f4246c.m(f.b.CREATED);
        super.onSaveInstanceState(bundle);
    }

    protected final boolean x(String[] strArr) {
        return !y(strArr);
    }
}
