package com.google.android.exoplayer2.offline;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.scheduler.Requirements;
import java.util.HashMap;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p225i1.C2092a;
import p005b.p199l.p200a.p201a.p226j1.InterfaceC2095a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public abstract class DownloadService extends Service {

    /* renamed from: c */
    public static final HashMap<Class<? extends DownloadService>, C3289a> f9380c = new HashMap<>();

    /* renamed from: e */
    public C2092a f9381e;

    /* renamed from: f */
    public int f9382f;

    /* renamed from: g */
    public boolean f9383g;

    /* renamed from: h */
    public boolean f9384h;

    /* renamed from: i */
    public boolean f9385i;

    /* renamed from: com.google.android.exoplayer2.offline.DownloadService$a */
    public static final class C3289a {

        /* renamed from: a */
        public final C2092a f9386a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC2095a f9387b;

        /* renamed from: c */
        @Nullable
        public DownloadService f9388c;
    }

    /* renamed from: a */
    public abstract C2092a m4057a();

    @Override // android.app.Service
    @Nullable
    public final IBinder onBind(Intent intent) {
        throw new UnsupportedOperationException();
    }

    @Override // android.app.Service
    public void onCreate() {
        C3289a c3289a = f9380c.get(getClass());
        if (c3289a != null) {
            this.f9381e = c3289a.f9386a;
            C4195m.m4771I(c3289a.f9388c == null);
            c3289a.f9388c = this;
            Objects.requireNonNull(c3289a.f9386a);
            return;
        }
        C2092a m4057a = m4057a();
        this.f9381e = m4057a;
        if (m4057a.f4413b) {
            m4057a.f4413b = false;
            m4057a.f4412a++;
            throw null;
        }
        getApplicationContext();
        Objects.requireNonNull(this.f9381e);
        throw null;
    }

    @Override // android.app.Service
    public void onDestroy() {
        C3289a c3289a = f9380c.get(getClass());
        Objects.requireNonNull(c3289a);
        C3289a c3289a2 = c3289a;
        C4195m.m4771I(c3289a2.f9388c == this);
        c3289a2.f9388c = null;
        if (c3289a2.f9387b != null) {
            Objects.requireNonNull(c3289a2.f9386a);
            c3289a2.f9387b.cancel();
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i2, int i3) {
        String str;
        String str2;
        char c2;
        this.f9382f = i3;
        this.f9384h = false;
        if (intent != null) {
            str = intent.getAction();
            str2 = intent.getStringExtra("content_id");
            this.f9383g |= intent.getBooleanExtra("foreground", false) || "com.google.android.exoplayer.downloadService.action.RESTART".equals(str);
        } else {
            str = null;
            str2 = null;
        }
        if (str == null) {
            str = "com.google.android.exoplayer.downloadService.action.INIT";
        }
        C2092a c2092a = this.f9381e;
        Objects.requireNonNull(c2092a);
        switch (str.hashCode()) {
            case -1931239035:
                if (str.equals("com.google.android.exoplayer.downloadService.action.ADD_DOWNLOAD")) {
                    c2 = 0;
                    break;
                }
                c2 = 65535;
                break;
            case -932047176:
                if (str.equals("com.google.android.exoplayer.downloadService.action.RESUME_DOWNLOADS")) {
                    c2 = 1;
                    break;
                }
                c2 = 65535;
                break;
            case -871181424:
                if (str.equals("com.google.android.exoplayer.downloadService.action.RESTART")) {
                    c2 = 2;
                    break;
                }
                c2 = 65535;
                break;
            case -650547439:
                if (str.equals("com.google.android.exoplayer.downloadService.action.REMOVE_ALL_DOWNLOADS")) {
                    c2 = 3;
                    break;
                }
                c2 = 65535;
                break;
            case -119057172:
                if (str.equals("com.google.android.exoplayer.downloadService.action.SET_REQUIREMENTS")) {
                    c2 = 4;
                    break;
                }
                c2 = 65535;
                break;
            case 191112771:
                if (str.equals("com.google.android.exoplayer.downloadService.action.PAUSE_DOWNLOADS")) {
                    c2 = 5;
                    break;
                }
                c2 = 65535;
                break;
            case 671523141:
                if (str.equals("com.google.android.exoplayer.downloadService.action.SET_STOP_REASON")) {
                    c2 = 6;
                    break;
                }
                c2 = 65535;
                break;
            case 1015676687:
                if (str.equals("com.google.android.exoplayer.downloadService.action.INIT")) {
                    c2 = 7;
                    break;
                }
                c2 = 65535;
                break;
            case 1547520644:
                if (str.equals("com.google.android.exoplayer.downloadService.action.REMOVE_DOWNLOAD")) {
                    c2 = '\b';
                    break;
                }
                c2 = 65535;
                break;
            default:
                c2 = 65535;
                break;
        }
        if (c2 != 0) {
            if (c2 != 1) {
                if (c2 == 3) {
                    c2092a.f4412a++;
                    throw null;
                }
                if (c2 != 4) {
                    if (c2 != 5) {
                        if (c2 != 6) {
                            if (c2 == '\b' && str2 != null) {
                                c2092a.f4412a++;
                                throw null;
                            }
                        } else if (intent.hasExtra("stop_reason")) {
                            intent.getIntExtra("stop_reason", 0);
                            c2092a.f4412a++;
                            throw null;
                        }
                    } else if (!c2092a.f4413b) {
                        c2092a.f4413b = true;
                        c2092a.f4412a++;
                        throw null;
                    }
                } else if (((Requirements) intent.getParcelableExtra("requirements")) != null) {
                    throw null;
                }
            } else if (c2092a.f4413b) {
                c2092a.f4413b = false;
                c2092a.f4412a++;
                throw null;
            }
        } else if (((DownloadRequest) intent.getParcelableExtra("download_request")) != null) {
            intent.getIntExtra("stop_reason", 0);
            c2092a.f4412a++;
            throw null;
        }
        int i4 = C2344d0.f6035a;
        this.f9385i = false;
        if (c2092a.f4412a == 0) {
            if (i4 >= 28 || !this.f9384h) {
                this.f9385i = stopSelfResult(this.f9382f) | false;
            } else {
                stopSelf();
                this.f9385i = true;
            }
        }
        return 1;
    }

    @Override // android.app.Service
    public void onTaskRemoved(Intent intent) {
        this.f9384h = true;
    }
}
