package c1;

import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.KeyEvent;

/* JADX INFO: renamed from: c1.p, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractActivityC0344p extends androidx.appcompat.app.c implements A1.a, A1.f {

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final AbstractC0347t f5655C = o0();

    protected AbstractActivityC0344p() {
    }

    @Override // A1.a
    public void c() {
        super.onBackPressed();
    }

    @Override // A1.f
    public void i(String[] strArr, int i3, A1.g gVar) {
        this.f5655C.D(strArr, i3, gVar);
    }

    protected abstract AbstractC0347t o0();

    @Override // androidx.fragment.app.AbstractActivityC0298j, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i3, int i4, Intent intent) {
        super.onActivityResult(i3, i4, intent);
        this.f5655C.p(i3, i4, intent);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (this.f5655C.q()) {
            return;
        }
        super.onBackPressed();
    }

    @Override // androidx.appcompat.app.c, androidx.activity.ComponentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.f5655C.r(configuration);
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, androidx.activity.ComponentActivity, androidx.core.app.f, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f5655C.s(bundle);
    }

    @Override // androidx.appcompat.app.c, androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        this.f5655C.t();
    }

    @Override // androidx.appcompat.app.c, android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyDown(int i3, KeyEvent keyEvent) {
        return this.f5655C.u(i3, keyEvent) || super.onKeyDown(i3, keyEvent);
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyLongPress(int i3, KeyEvent keyEvent) {
        return this.f5655C.v(i3, keyEvent) || super.onKeyLongPress(i3, keyEvent);
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyUp(int i3, KeyEvent keyEvent) {
        return this.f5655C.w(i3, keyEvent) || super.onKeyUp(i3, keyEvent);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onNewIntent(Intent intent) {
        if (this.f5655C.x(intent)) {
            return;
        }
        super.onNewIntent(intent);
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onPause() {
        super.onPause();
        this.f5655C.y();
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i3, String[] strArr, int[] iArr) {
        super.onRequestPermissionsResult(i3, strArr, iArr);
        this.f5655C.z(i3, strArr, iArr);
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onResume() {
        super.onResume();
        this.f5655C.A();
    }

    @Override // android.app.Activity
    public void onUserLeaveHint() {
        super.onUserLeaveHint();
        this.f5655C.B();
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onWindowFocusChanged(boolean z3) {
        super.onWindowFocusChanged(z3);
        this.f5655C.C(z3);
    }
}
