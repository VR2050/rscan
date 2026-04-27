package androidx.emoji2.text;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.graphics.Typeface;
import android.os.Handler;
import androidx.emoji2.text.f;
import java.nio.ByteBuffer;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import p.g;

/* JADX INFO: loaded from: classes.dex */
public class k extends f.c {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final a f4660k = new a();

    public static class a {
        public Typeface a(Context context, g.b bVar) {
            return p.g.a(context, null, new g.b[]{bVar});
        }

        public g.a b(Context context, p.e eVar) {
            return p.g.b(context, null, eVar);
        }

        public void c(Context context, ContentObserver contentObserver) {
            context.getContentResolver().unregisterContentObserver(contentObserver);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class b implements f.h {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Context f4661a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final p.e f4662b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final a f4663c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Object f4664d = new Object();

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private Handler f4665e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private Executor f4666f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private ThreadPoolExecutor f4667g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        f.i f4668h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private ContentObserver f4669i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private Runnable f4670j;

        b(Context context, p.e eVar, a aVar) {
            q.g.g(context, "Context cannot be null");
            q.g.g(eVar, "FontRequest cannot be null");
            this.f4661a = context.getApplicationContext();
            this.f4662b = eVar;
            this.f4663c = aVar;
        }

        private void b() {
            synchronized (this.f4664d) {
                try {
                    this.f4668h = null;
                    ContentObserver contentObserver = this.f4669i;
                    if (contentObserver != null) {
                        this.f4663c.c(this.f4661a, contentObserver);
                        this.f4669i = null;
                    }
                    Handler handler = this.f4665e;
                    if (handler != null) {
                        handler.removeCallbacks(this.f4670j);
                    }
                    this.f4665e = null;
                    ThreadPoolExecutor threadPoolExecutor = this.f4667g;
                    if (threadPoolExecutor != null) {
                        threadPoolExecutor.shutdown();
                    }
                    this.f4666f = null;
                    this.f4667g = null;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        private g.b e() {
            try {
                g.a aVarB = this.f4663c.b(this.f4661a, this.f4662b);
                if (aVarB.c() == 0) {
                    g.b[] bVarArrB = aVarB.b();
                    if (bVarArrB == null || bVarArrB.length == 0) {
                        throw new RuntimeException("fetchFonts failed (empty result)");
                    }
                    return bVarArrB[0];
                }
                throw new RuntimeException("fetchFonts failed (" + aVarB.c() + ")");
            } catch (PackageManager.NameNotFoundException e3) {
                throw new RuntimeException("provider not found", e3);
            }
        }

        @Override // androidx.emoji2.text.f.h
        public void a(f.i iVar) {
            q.g.g(iVar, "LoaderCallback cannot be null");
            synchronized (this.f4664d) {
                this.f4668h = iVar;
            }
            d();
        }

        void c() {
            synchronized (this.f4664d) {
                try {
                    if (this.f4668h == null) {
                        return;
                    }
                    try {
                        g.b bVarE = e();
                        int iB = bVarE.b();
                        if (iB == 2) {
                            synchronized (this.f4664d) {
                            }
                        }
                        if (iB != 0) {
                            throw new RuntimeException("fetchFonts result is not OK. (" + iB + ")");
                        }
                        try {
                            androidx.core.os.f.a("EmojiCompat.FontRequestEmojiCompatConfig.buildTypeface");
                            Typeface typefaceA = this.f4663c.a(this.f4661a, bVarE);
                            ByteBuffer byteBufferF = androidx.core.graphics.k.f(this.f4661a, null, bVarE.d());
                            if (byteBufferF == null || typefaceA == null) {
                                throw new RuntimeException("Unable to open file.");
                            }
                            n nVarB = n.b(typefaceA, byteBufferF);
                            androidx.core.os.f.b();
                            synchronized (this.f4664d) {
                                try {
                                    f.i iVar = this.f4668h;
                                    if (iVar != null) {
                                        iVar.b(nVarB);
                                    }
                                } finally {
                                }
                            }
                            b();
                        } catch (Throwable th) {
                            androidx.core.os.f.b();
                            throw th;
                        }
                    } catch (Throwable th2) {
                        synchronized (this.f4664d) {
                            try {
                                f.i iVar2 = this.f4668h;
                                if (iVar2 != null) {
                                    iVar2.a(th2);
                                }
                                b();
                            } finally {
                            }
                        }
                    }
                } finally {
                }
            }
        }

        void d() {
            synchronized (this.f4664d) {
                try {
                    if (this.f4668h == null) {
                        return;
                    }
                    if (this.f4666f == null) {
                        ThreadPoolExecutor threadPoolExecutorB = c.b("emojiCompat");
                        this.f4667g = threadPoolExecutorB;
                        this.f4666f = threadPoolExecutorB;
                    }
                    this.f4666f.execute(new Runnable() { // from class: androidx.emoji2.text.l
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f4671b.c();
                        }
                    });
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        public void f(Executor executor) {
            synchronized (this.f4664d) {
                this.f4666f = executor;
            }
        }
    }

    public k(Context context, p.e eVar) {
        super(new b(context, eVar, f4660k));
    }

    public k c(Executor executor) {
        ((b) a()).f(executor);
        return this;
    }
}
