package com.facebook.react.uimanager;

import java.util.Comparator;

/* JADX INFO: loaded from: classes.dex */
public class O0 {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static Comparator f7478c = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f7479a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f7480b;

    class a implements Comparator {
        a() {
        }

        @Override // java.util.Comparator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public int compare(O0 o02, O0 o03) {
            return o02.f7480b - o03.f7480b;
        }
    }

    public O0(int i3, int i4) {
        this.f7479a = i3;
        this.f7480b = i4;
    }

    public boolean equals(Object obj) {
        if (obj == null || obj.getClass() != getClass()) {
            return false;
        }
        O0 o02 = (O0) obj;
        return this.f7480b == o02.f7480b && this.f7479a == o02.f7479a;
    }

    public String toString() {
        return "[" + this.f7479a + ", " + this.f7480b + "]";
    }
}
