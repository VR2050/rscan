package p476m.p477a.p485b.p493l0;

import java.util.List;
import java.util.NoSuchElementException;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4804h;

/* renamed from: m.a.b.l0.j */
/* loaded from: classes3.dex */
public class C4862j implements InterfaceC4804h {

    /* renamed from: c */
    public final List<InterfaceC4800f> f12452c;

    /* renamed from: e */
    public int f12453e;

    /* renamed from: f */
    public int f12454f;

    /* renamed from: g */
    public String f12455g;

    public C4862j(List<InterfaceC4800f> list, String str) {
        C2354n.m2470e1(list, "Header list");
        this.f12452c = list;
        this.f12455g = str;
        this.f12453e = m5537a(-1);
        this.f12454f = -1;
    }

    /* renamed from: a */
    public int m5537a(int i2) {
        if (i2 < -1) {
            return -1;
        }
        int size = this.f12452c.size() - 1;
        boolean z = false;
        while (!z && i2 < size) {
            i2++;
            if (this.f12455g == null) {
                z = true;
            } else {
                z = this.f12455g.equalsIgnoreCase(this.f12452c.get(i2).getName());
            }
        }
        if (z) {
            return i2;
        }
        return -1;
    }

    @Override // p476m.p477a.p485b.InterfaceC4804h
    /* renamed from: b */
    public InterfaceC4800f mo5478b() {
        int i2 = this.f12453e;
        if (i2 < 0) {
            throw new NoSuchElementException("Iteration already finished.");
        }
        this.f12454f = i2;
        this.f12453e = m5537a(i2);
        return this.f12452c.get(i2);
    }

    @Override // p476m.p477a.p485b.InterfaceC4804h, java.util.Iterator
    public boolean hasNext() {
        return this.f12453e >= 0;
    }

    @Override // java.util.Iterator
    public final Object next() {
        return mo5478b();
    }

    @Override // java.util.Iterator
    public void remove() {
        int i2 = this.f12454f;
        if (!(i2 >= 0)) {
            throw new IllegalStateException("No header to remove");
        }
        this.f12452c.remove(i2);
        this.f12454f = -1;
        this.f12453e--;
    }
}
