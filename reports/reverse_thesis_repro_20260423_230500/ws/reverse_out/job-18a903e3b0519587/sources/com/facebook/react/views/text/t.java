package com.facebook.react.views.text;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class t {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f8177b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final t f8178c = new t("NONE", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final t f8179d = new t("UPPERCASE", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final t f8180e = new t("LOWERCASE", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final t f8181f = new t("CAPITALIZE", 3);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final t f8182g = new t("UNSET", 4);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ t[] f8183h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f8184i;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final String a(String str, t tVar) {
            if (str != null) {
                return u.a(str, tVar);
            }
            return null;
        }

        private a() {
        }
    }

    static {
        t[] tVarArrA = a();
        f8183h = tVarArrA;
        f8184i = AbstractC0628a.a(tVarArrA);
        f8177b = new a(null);
    }

    private t(String str, int i3) {
    }

    private static final /* synthetic */ t[] a() {
        return new t[]{f8178c, f8179d, f8180e, f8181f, f8182g};
    }

    public static final String b(String str, t tVar) {
        return f8177b.a(str, tVar);
    }

    public static t valueOf(String str) {
        return (t) Enum.valueOf(t.class, str);
    }

    public static t[] values() {
        return (t[]) f8183h.clone();
    }
}
