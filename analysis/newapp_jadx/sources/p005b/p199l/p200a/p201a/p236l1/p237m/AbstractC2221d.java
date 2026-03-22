package p005b.p199l.p200a.p201a.p236l1.p237m;

import androidx.annotation.NonNull;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.PriorityQueue;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2215j;
import p005b.p199l.p200a.p201a.p236l1.C2214i;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2211f;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.m.d */
/* loaded from: classes.dex */
public abstract class AbstractC2221d implements InterfaceC2211f {

    /* renamed from: a */
    public final ArrayDeque<b> f5389a = new ArrayDeque<>();

    /* renamed from: b */
    public final ArrayDeque<AbstractC2215j> f5390b;

    /* renamed from: c */
    public final PriorityQueue<b> f5391c;

    /* renamed from: d */
    public b f5392d;

    /* renamed from: e */
    public long f5393e;

    /* renamed from: f */
    public long f5394f;

    /* renamed from: b.l.a.a.l1.m.d$b */
    public static final class b extends C2214i implements Comparable<b> {

        /* renamed from: j */
        public long f5395j;

        public b() {
        }

        @Override // java.lang.Comparable
        public int compareTo(@NonNull b bVar) {
            b bVar2 = bVar;
            if (isEndOfStream() == bVar2.isEndOfStream()) {
                long j2 = this.f3307f - bVar2.f3307f;
                if (j2 == 0) {
                    j2 = this.f5395j - bVar2.f5395j;
                    if (j2 == 0) {
                        return 0;
                    }
                }
                if (j2 > 0) {
                    return 1;
                }
            } else if (isEndOfStream()) {
                return 1;
            }
            return -1;
        }

        public b(a aVar) {
        }
    }

    /* renamed from: b.l.a.a.l1.m.d$c */
    public final class c extends AbstractC2215j {
        public c(a aVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p204c1.AbstractC1946f
        public final void release() {
            AbstractC2221d abstractC2221d = AbstractC2221d.this;
            Objects.requireNonNull(abstractC2221d);
            clear();
            abstractC2221d.f5390b.add(this);
        }
    }

    public AbstractC2221d() {
        for (int i2 = 0; i2 < 10; i2++) {
            this.f5389a.add(new b(null));
        }
        this.f5390b = new ArrayDeque<>();
        for (int i3 = 0; i3 < 2; i3++) {
            this.f5390b.add(new c(null));
        }
        this.f5391c = new PriorityQueue<>();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2211f
    /* renamed from: a */
    public void mo2046a(long j2) {
        this.f5393e = j2;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    /* renamed from: b */
    public AbstractC2215j mo1377b() {
        if (this.f5390b.isEmpty()) {
            return null;
        }
        while (!this.f5391c.isEmpty() && this.f5391c.peek().f3307f <= this.f5393e) {
            b poll = this.f5391c.poll();
            if (poll.isEndOfStream()) {
                AbstractC2215j pollFirst = this.f5390b.pollFirst();
                pollFirst.addFlag(4);
                m2080h(poll);
                return pollFirst;
            }
            mo2058f(poll);
            if (mo2059g()) {
                InterfaceC2210e mo2057e = mo2057e();
                if (!poll.isDecodeOnly()) {
                    AbstractC2215j pollFirst2 = this.f5390b.pollFirst();
                    long j2 = poll.f3307f;
                    pollFirst2.timeUs = j2;
                    pollFirst2.f5292c = mo2057e;
                    pollFirst2.f5293e = j2;
                    m2080h(poll);
                    return pollFirst2;
                }
            }
            m2080h(poll);
        }
        return null;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    /* renamed from: c */
    public C2214i mo1378c() {
        C4195m.m4771I(this.f5392d == null);
        if (this.f5389a.isEmpty()) {
            return null;
        }
        b pollFirst = this.f5389a.pollFirst();
        this.f5392d = pollFirst;
        return pollFirst;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    /* renamed from: d */
    public void mo1379d(C2214i c2214i) {
        C2214i c2214i2 = c2214i;
        C4195m.m4765F(c2214i2 == this.f5392d);
        if (c2214i2.isDecodeOnly()) {
            m2080h(this.f5392d);
        } else {
            b bVar = this.f5392d;
            long j2 = this.f5394f;
            this.f5394f = 1 + j2;
            bVar.f5395j = j2;
            this.f5391c.add(bVar);
        }
        this.f5392d = null;
    }

    /* renamed from: e */
    public abstract InterfaceC2210e mo2057e();

    /* renamed from: f */
    public abstract void mo2058f(C2214i c2214i);

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    public void flush() {
        this.f5394f = 0L;
        this.f5393e = 0L;
        while (!this.f5391c.isEmpty()) {
            m2080h(this.f5391c.poll());
        }
        b bVar = this.f5392d;
        if (bVar != null) {
            m2080h(bVar);
            this.f5392d = null;
        }
    }

    /* renamed from: g */
    public abstract boolean mo2059g();

    /* renamed from: h */
    public final void m2080h(b bVar) {
        bVar.clear();
        this.f5389a.add(bVar);
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    public void release() {
    }
}
