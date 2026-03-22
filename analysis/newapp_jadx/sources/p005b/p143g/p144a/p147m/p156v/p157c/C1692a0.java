package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Queue;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.p157c.C1709n;
import p005b.p143g.p144a.p170s.C1801c;
import p005b.p143g.p144a.p170s.C1805g;

/* renamed from: b.g.a.m.v.c.a0 */
/* loaded from: classes.dex */
public class C1692a0 implements InterfaceC1584p<InputStream, Bitmap> {

    /* renamed from: a */
    public final C1709n f2462a;

    /* renamed from: b */
    public final InterfaceC1612b f2463b;

    /* renamed from: b.g.a.m.v.c.a0$a */
    public static class a implements C1709n.b {

        /* renamed from: a */
        public final C1719x f2464a;

        /* renamed from: b */
        public final C1801c f2465b;

        public a(C1719x c1719x, C1801c c1801c) {
            this.f2464a = c1719x;
            this.f2465b = c1801c;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b
        /* renamed from: a */
        public void mo985a(InterfaceC1614d interfaceC1614d, Bitmap bitmap) {
            IOException iOException = this.f2465b.f2754f;
            if (iOException != null) {
                if (bitmap == null) {
                    throw iOException;
                }
                interfaceC1614d.mo870d(bitmap);
                throw iOException;
            }
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b
        /* renamed from: b */
        public void mo986b() {
            C1719x c1719x = this.f2464a;
            synchronized (c1719x) {
                c1719x.f2542f = c1719x.f2540c.length;
            }
        }
    }

    public C1692a0(C1709n c1709n, InterfaceC1612b interfaceC1612b) {
        this.f2462a = c1709n;
        this.f2463b = interfaceC1612b;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull InputStream inputStream, @NonNull C1582n c1582n) {
        Objects.requireNonNull(this.f2462a);
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull InputStream inputStream, int i2, int i3, @NonNull C1582n c1582n) {
        C1719x c1719x;
        boolean z;
        C1801c poll;
        InputStream inputStream2 = inputStream;
        if (inputStream2 instanceof C1719x) {
            c1719x = (C1719x) inputStream2;
            z = false;
        } else {
            c1719x = new C1719x(inputStream2, this.f2463b);
            z = true;
        }
        Queue<C1801c> queue = C1801c.f2752c;
        synchronized (queue) {
            poll = queue.poll();
        }
        if (poll == null) {
            poll = new C1801c();
        }
        poll.f2753e = c1719x;
        try {
            return this.f2462a.m1014b(new C1805g(poll), i2, i3, c1582n, new a(c1719x, poll));
        } finally {
            poll.m1137b();
            if (z) {
                c1719x.m1026d();
            }
        }
    }
}
