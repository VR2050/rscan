package p005b.p199l.p200a.p201a.p251q1;

import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.view.Choreographer;
import android.view.WindowManager;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.q1.o */
/* loaded from: classes.dex */
public final class C2383o {

    /* renamed from: a */
    public final WindowManager f6248a;

    /* renamed from: b */
    public final b f6249b;

    /* renamed from: c */
    public final a f6250c;

    /* renamed from: d */
    public long f6251d;

    /* renamed from: e */
    public long f6252e;

    /* renamed from: f */
    public long f6253f;

    /* renamed from: g */
    public long f6254g;

    /* renamed from: h */
    public long f6255h;

    /* renamed from: i */
    public boolean f6256i;

    /* renamed from: j */
    public long f6257j;

    /* renamed from: k */
    public long f6258k;

    /* renamed from: l */
    public long f6259l;

    @TargetApi(17)
    /* renamed from: b.l.a.a.q1.o$a */
    public final class a implements DisplayManager.DisplayListener {

        /* renamed from: a */
        public final DisplayManager f6260a;

        public a(DisplayManager displayManager) {
            this.f6260a = displayManager;
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        public void onDisplayAdded(int i2) {
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        public void onDisplayChanged(int i2) {
            if (i2 == 0) {
                C2383o.this.m2638b();
            }
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        public void onDisplayRemoved(int i2) {
        }
    }

    /* renamed from: b.l.a.a.q1.o$b */
    public static final class b implements Choreographer.FrameCallback, Handler.Callback {

        /* renamed from: c */
        public static final b f6262c = new b();

        /* renamed from: e */
        public volatile long f6263e = -9223372036854775807L;

        /* renamed from: f */
        public final Handler f6264f;

        /* renamed from: g */
        public final HandlerThread f6265g;

        /* renamed from: h */
        public Choreographer f6266h;

        /* renamed from: i */
        public int f6267i;

        public b() {
            HandlerThread handlerThread = new HandlerThread("ChoreographerOwner:Handler");
            this.f6265g = handlerThread;
            handlerThread.start();
            Looper looper = handlerThread.getLooper();
            int i2 = C2344d0.f6035a;
            Handler handler = new Handler(looper, this);
            this.f6264f = handler;
            handler.sendEmptyMessage(0);
        }

        @Override // android.view.Choreographer.FrameCallback
        public void doFrame(long j2) {
            this.f6263e = j2;
            this.f6266h.postFrameCallbackDelayed(this, 500L);
        }

        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            int i2 = message.what;
            if (i2 == 0) {
                this.f6266h = Choreographer.getInstance();
                return true;
            }
            if (i2 == 1) {
                int i3 = this.f6267i + 1;
                this.f6267i = i3;
                if (i3 == 1) {
                    this.f6266h.postFrameCallback(this);
                }
                return true;
            }
            if (i2 != 2) {
                return false;
            }
            int i4 = this.f6267i - 1;
            this.f6267i = i4;
            if (i4 == 0) {
                this.f6266h.removeFrameCallback(this);
                this.f6263e = -9223372036854775807L;
            }
            return true;
        }
    }

    public C2383o(@Nullable Context context) {
        DisplayManager displayManager;
        a aVar = null;
        if (context != null) {
            context = context.getApplicationContext();
            this.f6248a = (WindowManager) context.getSystemService("window");
        } else {
            this.f6248a = null;
        }
        if (this.f6248a != null) {
            if (C2344d0.f6035a >= 17 && (displayManager = (DisplayManager) context.getSystemService("display")) != null) {
                aVar = new a(displayManager);
            }
            this.f6250c = aVar;
            this.f6249b = b.f6262c;
        } else {
            this.f6250c = null;
            this.f6249b = null;
        }
        this.f6251d = -9223372036854775807L;
        this.f6252e = -9223372036854775807L;
    }

    /* renamed from: a */
    public final boolean m2637a(long j2, long j3) {
        return Math.abs((j3 - this.f6257j) - (j2 - this.f6258k)) > 20000000;
    }

    /* renamed from: b */
    public final void m2638b() {
        if (this.f6248a.getDefaultDisplay() != null) {
            long refreshRate = (long) (1.0E9d / r0.getRefreshRate());
            this.f6251d = refreshRate;
            this.f6252e = (refreshRate * 80) / 100;
        }
    }
}
