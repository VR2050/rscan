package p005b.p172h.p173a;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import java.io.File;
import java.net.Socket;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import p005b.p172h.p173a.p174r.C1830b;

/* renamed from: b.h.a.h */
/* loaded from: classes.dex */
public final class C1819h {

    /* renamed from: a */
    public final AtomicInteger f2800a = new AtomicInteger(0);

    /* renamed from: b */
    public final String f2801b;

    /* renamed from: c */
    public volatile C1816e f2802c;

    /* renamed from: d */
    public final List<InterfaceC1813b> f2803d;

    /* renamed from: e */
    public final InterfaceC1813b f2804e;

    /* renamed from: f */
    public final C1814c f2805f;

    /* renamed from: b.h.a.h$a */
    public static final class a extends Handler implements InterfaceC1813b {

        /* renamed from: c */
        public final String f2806c;

        /* renamed from: e */
        public final List<InterfaceC1813b> f2807e;

        public a(String str, List<InterfaceC1813b> list) {
            super(Looper.getMainLooper());
            this.f2806c = str;
            this.f2807e = list;
        }

        @Override // p005b.p172h.p173a.InterfaceC1813b
        /* renamed from: a */
        public void mo1159a(File file, String str, int i2) {
            Message obtainMessage = obtainMessage();
            obtainMessage.arg1 = i2;
            obtainMessage.obj = file;
            sendMessage(obtainMessage);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            Iterator<InterfaceC1813b> it = this.f2807e.iterator();
            while (it.hasNext()) {
                it.next().mo1159a((File) message.obj, this.f2806c, message.arg1);
            }
        }
    }

    public C1819h(String str, C1814c c1814c) {
        CopyOnWriteArrayList copyOnWriteArrayList = new CopyOnWriteArrayList();
        this.f2803d = copyOnWriteArrayList;
        Objects.requireNonNull(str);
        this.f2801b = str;
        Objects.requireNonNull(c1814c);
        this.f2805f = c1814c;
        this.f2804e = new a(str, copyOnWriteArrayList);
    }

    /* renamed from: a */
    public final synchronized void m1173a() {
        if (this.f2800a.decrementAndGet() <= 0) {
            this.f2802c.m1185f();
            this.f2802c = null;
        }
    }

    /* renamed from: b */
    public final C1816e m1174b() {
        String str = this.f2801b;
        C1814c c1814c = this.f2805f;
        C1820i c1820i = new C1820i(str, c1814c.f2778d, c1814c.f2779e);
        C1814c c1814c2 = this.f2805f;
        C1816e c1816e = new C1816e(c1820i, new C1830b(new File(c1814c2.f2775a, c1814c2.f2776b.m1189a(this.f2801b)), this.f2805f.f2777c));
        c1816e.f2787k = this.f2804e;
        return c1816e;
    }

    /* renamed from: c */
    public void m1175c(C1815d c1815d, Socket socket) {
        synchronized (this) {
            this.f2802c = this.f2802c == null ? m1174b() : this.f2802c;
        }
        try {
            this.f2800a.incrementAndGet();
            this.f2802c.m1163h(c1815d, socket);
        } finally {
            m1173a();
        }
    }
}
