package p005b.p143g.p144a.p147m.p150t;

import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.EnumC1571c;

/* renamed from: b.g.a.m.t.k */
/* loaded from: classes.dex */
public abstract class AbstractC1643k {

    /* renamed from: a */
    public static final AbstractC1643k f2222a = new a();

    /* renamed from: b */
    public static final AbstractC1643k f2223b = new b();

    /* renamed from: c */
    public static final AbstractC1643k f2224c = new c();

    /* renamed from: d */
    public static final AbstractC1643k f2225d = new d();

    /* renamed from: b.g.a.m.t.k$a */
    public class a extends AbstractC1643k {
        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: a */
        public boolean mo927a() {
            return true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: b */
        public boolean mo928b() {
            return true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: c */
        public boolean mo929c(EnumC1569a enumC1569a) {
            return enumC1569a == EnumC1569a.REMOTE;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: d */
        public boolean mo930d(boolean z, EnumC1569a enumC1569a, EnumC1571c enumC1571c) {
            return (enumC1569a == EnumC1569a.RESOURCE_DISK_CACHE || enumC1569a == EnumC1569a.MEMORY_CACHE) ? false : true;
        }
    }

    /* renamed from: b.g.a.m.t.k$b */
    public class b extends AbstractC1643k {
        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: a */
        public boolean mo927a() {
            return false;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: b */
        public boolean mo928b() {
            return false;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: c */
        public boolean mo929c(EnumC1569a enumC1569a) {
            return false;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: d */
        public boolean mo930d(boolean z, EnumC1569a enumC1569a, EnumC1571c enumC1571c) {
            return false;
        }
    }

    /* renamed from: b.g.a.m.t.k$c */
    public class c extends AbstractC1643k {
        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: a */
        public boolean mo927a() {
            return true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: b */
        public boolean mo928b() {
            return false;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: c */
        public boolean mo929c(EnumC1569a enumC1569a) {
            return (enumC1569a == EnumC1569a.DATA_DISK_CACHE || enumC1569a == EnumC1569a.MEMORY_CACHE) ? false : true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: d */
        public boolean mo930d(boolean z, EnumC1569a enumC1569a, EnumC1571c enumC1571c) {
            return false;
        }
    }

    /* renamed from: b.g.a.m.t.k$d */
    public class d extends AbstractC1643k {
        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: a */
        public boolean mo927a() {
            return true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: b */
        public boolean mo928b() {
            return true;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: c */
        public boolean mo929c(EnumC1569a enumC1569a) {
            return enumC1569a == EnumC1569a.REMOTE;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.AbstractC1643k
        /* renamed from: d */
        public boolean mo930d(boolean z, EnumC1569a enumC1569a, EnumC1571c enumC1571c) {
            return ((z && enumC1569a == EnumC1569a.DATA_DISK_CACHE) || enumC1569a == EnumC1569a.LOCAL) && enumC1571c == EnumC1571c.TRANSFORMED;
        }
    }

    /* renamed from: a */
    public abstract boolean mo927a();

    /* renamed from: b */
    public abstract boolean mo928b();

    /* renamed from: c */
    public abstract boolean mo929c(EnumC1569a enumC1569a);

    /* renamed from: d */
    public abstract boolean mo930d(boolean z, EnumC1569a enumC1569a, EnumC1571c enumC1571c);
}
