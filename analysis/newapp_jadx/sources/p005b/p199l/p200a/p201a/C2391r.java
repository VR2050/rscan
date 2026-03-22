package p005b.p199l.p200a.p201a;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;

/* renamed from: b.l.a.a.r */
/* loaded from: classes.dex */
public final class C2391r {

    /* renamed from: a */
    public final Context f6288a;

    /* renamed from: b */
    public final a f6289b;

    /* renamed from: c */
    public boolean f6290c;

    /* renamed from: b.l.a.a.r$a */
    public final class a extends BroadcastReceiver implements Runnable {

        /* renamed from: c */
        public final b f6291c;

        /* renamed from: e */
        public final Handler f6292e;

        public a(Handler handler, b bVar) {
            this.f6292e = handler;
            this.f6291c = bVar;
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if ("android.media.AUDIO_BECOMING_NOISY".equals(intent.getAction())) {
                this.f6292e.post(this);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C2391r.this.f6290c) {
                C2402w0.this.mo1368p(false);
            }
        }
    }

    /* renamed from: b.l.a.a.r$b */
    public interface b {
    }

    public C2391r(Context context, Handler handler, b bVar) {
        this.f6288a = context.getApplicationContext();
        this.f6289b = new a(handler, bVar);
    }
}
