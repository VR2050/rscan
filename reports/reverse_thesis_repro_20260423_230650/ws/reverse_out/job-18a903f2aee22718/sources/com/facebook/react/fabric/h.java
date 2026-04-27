package com.facebook.react.fabric;

import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f6961a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6962b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f6963c;

    public h(int i3, int i4, String str) {
        j.f(str, "eventName");
        this.f6961a = i3;
        this.f6962b = i4;
        this.f6963c = str;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.f6961a == hVar.f6961a && this.f6962b == hVar.f6962b && j.b(this.f6963c, hVar.f6963c);
    }

    public int hashCode() {
        return (((Integer.hashCode(this.f6961a) * 31) + Integer.hashCode(this.f6962b)) * 31) + this.f6963c.hashCode();
    }

    public String toString() {
        return "SynchronousEvent(surfaceId=" + this.f6961a + ", viewTag=" + this.f6962b + ", eventName=" + this.f6963c + ")";
    }
}
