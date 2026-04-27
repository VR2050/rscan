package com.facebook.react.common.mapbuffer;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX INFO: loaded from: classes.dex */
public interface a extends Iterable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0101a f6667a = C0101a.f6668a;

    /* JADX INFO: renamed from: com.facebook.react.common.mapbuffer.a$a, reason: collision with other inner class name */
    public static final class C0101a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ C0101a f6668a = new C0101a();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private static final w2.c f6669b = new w2.c(0, 65535);

        private C0101a() {
        }

        public final w2.c a() {
            return f6669b;
        }
    }

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    public static final class b {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final b f6670b = new b("BOOL", 0);

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final b f6671c = new b("INT", 1);

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final b f6672d = new b("DOUBLE", 2);

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public static final b f6673e = new b("STRING", 3);

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public static final b f6674f = new b("MAP", 4);

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public static final b f6675g = new b("LONG", 5);

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private static final /* synthetic */ b[] f6676h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private static final /* synthetic */ EnumEntries f6677i;

        static {
            b[] bVarArrA = a();
            f6676h = bVarArrA;
            f6677i = AbstractC0628a.a(bVarArrA);
        }

        private b(String str, int i3) {
        }

        private static final /* synthetic */ b[] a() {
            return new b[]{f6670b, f6671c, f6672d, f6673e, f6674f, f6675g};
        }

        public static b valueOf(String str) {
            return (b) Enum.valueOf(b.class, str);
        }

        public static b[] values() {
            return (b[]) f6676h.clone();
        }
    }

    public interface c {
        long a();

        String b();

        int c();

        a d();

        double e();

        boolean f();

        int getKey();

        b getType();
    }

    a d(int i3);

    boolean g(int i3);

    boolean getBoolean(int i3);

    int getCount();

    double getDouble(int i3);

    int getInt(int i3);

    String getString(int i3);
}
