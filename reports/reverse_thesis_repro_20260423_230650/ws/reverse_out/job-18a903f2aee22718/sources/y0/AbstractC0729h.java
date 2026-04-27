package y0;

import java.util.ArrayList;
import java.util.List;

/* JADX INFO: renamed from: y0.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0729h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final EnumC0732k f10443a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final List f10444b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f10445c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Long f10446d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Long f10447e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private String f10448f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private String f10449g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private String[] f10450h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private String f10451i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private String f10452j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private String f10453k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private String f10454l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Long f10455m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private String f10456n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private String f10457o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private String f10458p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Integer f10459q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Integer f10460r;

    public AbstractC0729h(EnumC0732k enumC0732k) {
        t2.j.f(enumC0732k, "infra");
        this.f10443a = enumC0732k;
        this.f10444b = new ArrayList();
    }

    public final String a() {
        return this.f10448f;
    }

    public final String b() {
        return this.f10452j;
    }

    public final String[] c() {
        return this.f10450h;
    }

    public final String d() {
        return this.f10451i;
    }

    public final Integer e() {
        return this.f10460r;
    }

    public final Long f() {
        return this.f10446d;
    }

    public final Integer g() {
        return this.f10459q;
    }

    public final String h() {
        return this.f10457o;
    }

    public final String i() {
        return this.f10458p;
    }

    public final EnumC0732k j() {
        return this.f10443a;
    }

    public final List k() {
        return this.f10444b;
    }

    public final Long l() {
        return this.f10455m;
    }

    public final boolean m() {
        return this.f10445c;
    }

    public final Long n() {
        return this.f10447e;
    }

    public final String o() {
        return this.f10449g;
    }

    public final String p() {
        return this.f10456n;
    }

    public final String q() {
        return this.f10454l;
    }

    public final String r() {
        return this.f10453k;
    }

    public final void s() {
        this.f10444b.clear();
        this.f10445c = false;
        this.f10446d = null;
        this.f10447e = null;
        this.f10448f = null;
        this.f10449g = null;
        this.f10450h = null;
        this.f10451i = null;
        this.f10452j = null;
        this.f10453k = null;
        this.f10454l = null;
        this.f10455m = null;
        this.f10456n = null;
        this.f10457o = null;
        this.f10458p = null;
        this.f10459q = null;
        this.f10460r = null;
    }

    public final void t(Long l3) {
        this.f10446d = l3;
    }

    public final void u(boolean z3) {
        this.f10445c = z3;
    }

    public final void v(Long l3) {
        this.f10447e = l3;
    }
}
