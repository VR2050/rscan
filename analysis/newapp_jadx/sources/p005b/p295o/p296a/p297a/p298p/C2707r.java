package p005b.p295o.p296a.p297a.p298p;

import net.sourceforge.pinyin4j.ChineseToPinyinResource;

/* renamed from: b.o.a.a.p.r */
/* loaded from: classes2.dex */
public class C2707r {

    /* renamed from: a */
    public final AbstractC2703n f7377a;

    /* renamed from: b */
    public final AbstractC2700k f7378b;

    /* renamed from: c */
    public final boolean f7379c;

    public C2707r(C2689a0 c2689a0, boolean z, C2706q c2706q) {
        AbstractC2700k c2711v;
        int parseInt;
        int parseInt2;
        this.f7379c = z;
        int i2 = c2706q.f7368a;
        if (i2 != -3) {
            if (i2 == 42) {
                this.f7377a = C2688a.f7355a;
            } else if (i2 != 46) {
                if (i2 != 64) {
                    throw new C2691b0(c2689a0, "at begininning of step", c2706q, "'.' or '*' or name");
                }
                if (c2706q.m3235a() != -3) {
                    throw new C2691b0(c2689a0, "after @ in node test", c2706q, "name");
                }
                this.f7377a = new C2699j(c2706q.f7370c);
            } else if (c2706q.m3235a() == 46) {
                this.f7377a = C2704o.f7366a;
            } else {
                c2706q.f7375h = true;
                this.f7377a = C2713x.f7383a;
            }
        } else if (!c2706q.f7370c.equals("text")) {
            this.f7377a = new C2702m(c2706q.f7370c);
        } else {
            if (c2706q.m3235a() != 40 || c2706q.m3235a() != 41) {
                throw new C2691b0(c2689a0, "after text", c2706q, "()");
            }
            this.f7377a = C2712w.f7382a;
        }
        if (c2706q.m3235a() != 91) {
            this.f7378b = C2714y.f7384a;
            return;
        }
        c2706q.m3235a();
        int i3 = c2706q.f7368a;
        if (i3 != -3) {
            if (i3 == -2) {
                int i4 = c2706q.f7369b;
                c2706q.m3235a();
                c2711v = new C2705p(i4);
            } else {
                if (i3 != 64) {
                    throw new C2691b0(c2689a0, "at beginning of expression", c2706q, "@, number, or text()");
                }
                if (c2706q.m3235a() != -3) {
                    throw new C2691b0(c2689a0, "after @", c2706q, "name");
                }
                String str = c2706q.f7370c;
                int m3235a = c2706q.m3235a();
                if (m3235a != 33) {
                    switch (m3235a) {
                        case 60:
                            c2706q.m3235a();
                            int i5 = c2706q.f7368a;
                            if (i5 == 34 || i5 == 39) {
                                parseInt = Integer.parseInt(c2706q.f7370c);
                            } else {
                                if (i5 != -2) {
                                    throw new C2691b0(c2689a0, "right hand side of less-than", c2706q, "quoted string or number");
                                }
                                parseInt = c2706q.f7369b;
                            }
                            c2706q.m3235a();
                            c2711v = new C2696g(str, parseInt);
                            break;
                        case 61:
                            c2706q.m3235a();
                            int i6 = c2706q.f7368a;
                            if (i6 != 34 && i6 != 39) {
                                throw new C2691b0(c2689a0, "right hand side of equals", c2706q, "quoted string");
                            }
                            String str2 = c2706q.f7370c;
                            c2706q.m3235a();
                            c2711v = new C2692c(str, str2);
                            break;
                        case 62:
                            c2706q.m3235a();
                            int i7 = c2706q.f7368a;
                            if (i7 == 34 || i7 == 39) {
                                parseInt2 = Integer.parseInt(c2706q.f7370c);
                            } else {
                                if (i7 != -2) {
                                    throw new C2691b0(c2689a0, "right hand side of greater-than", c2706q, "quoted string or number");
                                }
                                parseInt2 = c2706q.f7369b;
                            }
                            c2706q.m3235a();
                            c2711v = new C2695f(str, parseInt2);
                            break;
                        default:
                            c2711v = new C2693d(str);
                            break;
                    }
                } else {
                    c2706q.m3235a();
                    if (c2706q.f7368a != 61) {
                        throw new C2691b0(c2689a0, "after !", c2706q, "=");
                    }
                    c2706q.m3235a();
                    int i8 = c2706q.f7368a;
                    if (i8 != 34 && i8 != 39) {
                        throw new C2691b0(c2689a0, "right hand side of !=", c2706q, "quoted string");
                    }
                    String str3 = c2706q.f7370c;
                    c2706q.m3235a();
                    c2711v = new C2697h(str, str3);
                }
            }
        } else {
            if (!c2706q.f7370c.equals("text")) {
                throw new C2691b0(c2689a0, "at beginning of expression", c2706q, "text()");
            }
            if (c2706q.m3235a() != 40) {
                throw new C2691b0(c2689a0, "after text", c2706q, ChineseToPinyinResource.Field.LEFT_BRACKET);
            }
            if (c2706q.m3235a() != 41) {
                throw new C2691b0(c2689a0, "after text(", c2706q, ChineseToPinyinResource.Field.RIGHT_BRACKET);
            }
            int m3235a2 = c2706q.m3235a();
            if (m3235a2 == 33) {
                c2706q.m3235a();
                if (c2706q.f7368a != 61) {
                    throw new C2691b0(c2689a0, "after !", c2706q, "=");
                }
                c2706q.m3235a();
                int i9 = c2706q.f7368a;
                if (i9 != 34 && i9 != 39) {
                    throw new C2691b0(c2689a0, "right hand side of !=", c2706q, "quoted string");
                }
                String str4 = c2706q.f7370c;
                c2706q.m3235a();
                c2711v = new C2711v(str4);
            } else if (m3235a2 != 61) {
                c2711v = C2710u.f7381a;
            } else {
                c2706q.m3235a();
                int i10 = c2706q.f7368a;
                if (i10 != 34 && i10 != 39) {
                    throw new C2691b0(c2689a0, "right hand side of equals", c2706q, "quoted string");
                }
                String str5 = c2706q.f7370c;
                c2706q.m3235a();
                c2711v = new C2709t(str5);
            }
        }
        this.f7378b = c2711v;
        if (c2706q.f7368a != 93) {
            throw new C2691b0(c2689a0, "after predicate expression", c2706q, "]");
        }
        c2706q.m3235a();
    }

    public String toString() {
        return this.f7377a.toString() + this.f7378b.toString();
    }
}
