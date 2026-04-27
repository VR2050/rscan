package com.facebook.react.devsupport;

import android.app.Activity;
import android.util.Pair;
import android.view.View;
import com.facebook.react.bridge.DefaultJSExceptionHandler;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.ReactContext;
import j1.InterfaceC0595d;
import j1.e;

/* JADX INFO: loaded from: classes.dex */
public class k0 implements j1.e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final JSExceptionHandler f6889a = new DefaultJSExceptionHandler();

    @Override // j1.e
    public void A(boolean z3) {
    }

    @Override // j1.e
    public j1.f B() {
        return null;
    }

    @Override // j1.e
    public ReactContext C() {
        return null;
    }

    @Override // j1.e
    public void D() {
    }

    @Override // j1.e
    public String E() {
        return null;
    }

    @Override // j1.e
    public View a(String str) {
        return null;
    }

    @Override // j1.e
    public void b(View view) {
    }

    @Override // j1.e
    public void c(boolean z3) {
    }

    @Override // j1.e
    public void d() {
    }

    @Override // j1.e
    public void e(boolean z3) {
    }

    @Override // j1.e
    public d1.j f(String str) {
        return null;
    }

    @Override // j1.e
    public void g() {
    }

    @Override // j1.e
    public void h(String str, e.a aVar) {
        t2.j.f(str, "message");
        t2.j.f(aVar, "listener");
    }

    @Override // com.facebook.react.bridge.JSExceptionHandler
    public void handleException(Exception exc) {
        t2.j.f(exc, "e");
        this.f6889a.handleException(exc);
    }

    @Override // j1.e
    public Activity i() {
        return null;
    }

    @Override // j1.e
    public String j() {
        return null;
    }

    @Override // j1.e
    public String k() {
        return null;
    }

    @Override // j1.e
    public void l() {
    }

    @Override // j1.e
    public boolean m() {
        return false;
    }

    @Override // j1.e
    public B1.a n() {
        return null;
    }

    @Override // j1.e
    public void o() {
    }

    @Override // j1.e
    public void p(ReactContext reactContext) {
        t2.j.f(reactContext, "reactContext");
    }

    @Override // j1.e
    public void q(j1.g gVar) {
        t2.j.f(gVar, "callback");
        gVar.a(false);
    }

    @Override // j1.e
    public void r() {
    }

    @Override // j1.e
    public j1.i s() {
        return null;
    }

    @Override // j1.e
    public void t() {
    }

    @Override // j1.e
    public boolean u() {
        return false;
    }

    @Override // j1.e
    public j1.j[] v() {
        return null;
    }

    @Override // j1.e
    public void w() {
    }

    @Override // j1.e
    public Pair x(Pair pair) {
        return pair;
    }

    @Override // j1.e
    public void z(ReactContext reactContext) {
        t2.j.f(reactContext, "reactContext");
    }

    @Override // j1.e
    public void y(String str, InterfaceC0595d interfaceC0595d) {
    }
}
