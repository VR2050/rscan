package p005b.p199l.p200a.p201a;

import android.content.Context;
import android.media.AudioManager;
import android.os.Handler;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2393s;
import p005b.p199l.p200a.p201a.C2402w0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.s */
/* loaded from: classes.dex */
public final class C2393s {

    /* renamed from: a */
    public final AudioManager f6304a;

    /* renamed from: b */
    public final a f6305b;

    /* renamed from: c */
    public final b f6306c;

    /* renamed from: e */
    public float f6308e = 1.0f;

    /* renamed from: d */
    public int f6307d = 0;

    /* renamed from: b.l.a.a.s$a */
    public class a implements AudioManager.OnAudioFocusChangeListener {

        /* renamed from: a */
        public final Handler f6309a;

        public a(Handler handler) {
            this.f6309a = handler;
        }

        @Override // android.media.AudioManager.OnAudioFocusChangeListener
        public void onAudioFocusChange(final int i2) {
            this.f6309a.post(new Runnable() { // from class: b.l.a.a.a
                @Override // java.lang.Runnable
                public final void run() {
                    C2393s.a aVar = C2393s.a.this;
                    int i3 = i2;
                    C2393s c2393s = C2393s.this;
                    Objects.requireNonNull(c2393s);
                    if (i3 == -3) {
                        c2393s.f6307d = 3;
                    } else if (i3 == -2) {
                        c2393s.f6307d = 2;
                    } else if (i3 == -1) {
                        c2393s.f6307d = -1;
                    } else if (i3 != 1) {
                        return;
                    } else {
                        c2393s.f6307d = 1;
                    }
                    int i4 = c2393s.f6307d;
                    if (i4 == -1) {
                        ((C2402w0.b) c2393s.f6306c).m2685a(-1);
                        c2393s.m2649a(true);
                    } else if (i4 != 0) {
                        if (i4 == 1) {
                            ((C2402w0.b) c2393s.f6306c).m2685a(1);
                        } else if (i4 == 2) {
                            ((C2402w0.b) c2393s.f6306c).m2685a(0);
                        } else if (i4 != 3) {
                            StringBuilder m586H = C1499a.m586H("Unknown audio focus state: ");
                            m586H.append(c2393s.f6307d);
                            throw new IllegalStateException(m586H.toString());
                        }
                    }
                    float f2 = c2393s.f6307d == 3 ? 0.2f : 1.0f;
                    if (c2393s.f6308e != f2) {
                        c2393s.f6308e = f2;
                        ((C2402w0.b) c2393s.f6306c).f6365c.m2675L();
                    }
                }
            });
        }
    }

    /* renamed from: b.l.a.a.s$b */
    public interface b {
    }

    public C2393s(Context context, Handler handler, b bVar) {
        this.f6304a = (AudioManager) context.getApplicationContext().getSystemService("audio");
        this.f6306c = bVar;
        this.f6305b = new a(handler);
    }

    /* renamed from: a */
    public final void m2649a(boolean z) {
        if (this.f6307d == 0) {
            return;
        }
        if (C2344d0.f6035a < 26) {
            this.f6304a.abandonAudioFocus(this.f6305b);
        }
        this.f6307d = 0;
    }
}
