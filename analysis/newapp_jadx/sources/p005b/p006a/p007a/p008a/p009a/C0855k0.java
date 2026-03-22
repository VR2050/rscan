package p005b.p006a.p007a.p008a.p009a;

import com.alibaba.fastjson.JSON;
import com.jbzd.media.movecartoons.bean.event.EventDownload;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Pattern;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.PropertyReference1Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.p472io.TextStreamsKt;
import kotlin.reflect.KProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2862f;
import p379c.p380a.InterfaceC3053d1;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p476m.p496b.p497a.C4909c;
import tv.danmaku.ijk.media.player.IjkMediaPlayer;

/* renamed from: b.a.a.a.a.k0 */
/* loaded from: classes2.dex */
public final class C0855k0 {

    /* renamed from: a */
    @NotNull
    public static final c f257a = new c(null);

    /* renamed from: b */
    @NotNull
    public static final C0855k0 f258b;

    /* renamed from: c */
    @NotNull
    public static final Lazy<String> f259c;

    /* renamed from: d */
    @NotNull
    public static final Lazy<Integer> f260d;

    /* renamed from: e */
    @NotNull
    public final Lazy f261e = LazyKt__LazyJVMKt.lazy(g.f273c);

    /* renamed from: f */
    @NotNull
    public final String f262f = "VideoDownloadController";

    /* renamed from: g */
    @NotNull
    public final Lazy f263g = LazyKt__LazyJVMKt.lazy(f.f272c);

    /* renamed from: h */
    @NotNull
    public final Lazy f264h = LazyKt__LazyJVMKt.lazy(h.f274c);

    /* renamed from: b.a.a.a.a.k0$a */
    public static final class a extends Lambda implements Function0<String> {

        /* renamed from: c */
        public static final a f265c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public String invoke() {
            Enumeration<NetworkInterface> enumeration;
            Pattern pattern = C2862f.f7796a;
            InetAddress inetAddress = null;
            try {
                enumeration = NetworkInterface.getNetworkInterfaces();
            } catch (SocketException e2) {
                e2.printStackTrace();
                enumeration = null;
            }
            if (enumeration != null) {
                loop0: while (true) {
                    if (!enumeration.hasMoreElements()) {
                        break;
                    }
                    Enumeration<InetAddress> inetAddresses = enumeration.nextElement().getInetAddresses();
                    if (inetAddresses != null) {
                        while (inetAddresses.hasMoreElements()) {
                            InetAddress nextElement = inetAddresses.nextElement();
                            if (!nextElement.isLoopbackAddress()) {
                                if (C2862f.f7796a.matcher(nextElement.getHostAddress()).matches()) {
                                    inetAddress = nextElement;
                                    break loop0;
                                }
                            }
                        }
                    }
                }
            }
            return inetAddress.getHostAddress();
        }
    }

    /* renamed from: b.a.a.a.a.k0$b */
    public static final class b extends Lambda implements Function0<Integer> {

        /* renamed from: c */
        public static final b f266c = new b();

        public b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Integer invoke() {
            return 53322;
        }
    }

    /* renamed from: b.a.a.a.a.k0$c */
    public static final class c {

        /* renamed from: a */
        public static final /* synthetic */ KProperty<Object>[] f267a = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(c.class), "address", "getAddress()Ljava/lang/String;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(c.class), IjkMediaPlayer.OnNativeInvokeListener.ARG_PORT, "getPort()I"))};

        public c() {
        }

        public c(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* renamed from: b.a.a.a.a.k0$d */
    public static final class d {

        /* renamed from: a */
        @NotNull
        public static final d f268a = null;

        /* renamed from: b */
        @NotNull
        public static final C0855k0 f269b = new C0855k0();
    }

    /* renamed from: b.a.a.a.a.k0$e */
    public static final class e extends Lambda implements Function1<DownloadVideoInfo, Unit> {

        /* renamed from: e */
        public final /* synthetic */ DownloadVideoInfo f271e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public e(DownloadVideoInfo downloadVideoInfo) {
            super(1);
            this.f271e = downloadVideoInfo;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(DownloadVideoInfo downloadVideoInfo) {
            DownloadVideoInfo it = downloadVideoInfo;
            Intrinsics.checkNotNullParameter(it, "it");
            if (Intrinsics.areEqual(it.status, "completed")) {
                C0855k0.this.m188d().remove(this.f271e.f9947id);
                DownloadVideoInfo info = C0855k0.this.m190f().poll();
                if (info != null) {
                    C0855k0 c0855k0 = C0855k0.this;
                    Intrinsics.checkNotNullExpressionValue(info, "info");
                    c0855k0.m185a(info);
                }
            } else if (Intrinsics.areEqual(it.status, "error")) {
                C0855k0.this.m188d().remove(this.f271e.f9947id);
                DownloadVideoInfo info2 = C0855k0.this.m190f().poll();
                if (info2 != null) {
                    C0855k0 c0855k02 = C0855k0.this;
                    Intrinsics.checkNotNullExpressionValue(info2, "info");
                    c0855k02.m185a(info2);
                }
            }
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.a.a.a.a.k0$f */
    public static final class f extends Lambda implements Function0<HashMap<String, RunnableC0860n>> {

        /* renamed from: c */
        public static final f f272c = new f();

        public f() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public HashMap<String, RunnableC0860n> invoke() {
            return new HashMap<>();
        }
    }

    /* renamed from: b.a.a.a.a.k0$g */
    public static final class g extends Lambda implements Function0<ExecutorService> {

        /* renamed from: c */
        public static final g f273c = new g();

        public g() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public ExecutorService invoke() {
            return Executors.newCachedThreadPool();
        }
    }

    /* renamed from: b.a.a.a.a.k0$h */
    public static final class h extends Lambda implements Function0<LinkedBlockingQueue<DownloadVideoInfo>> {

        /* renamed from: c */
        public static final h f274c = new h();

        public h() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public LinkedBlockingQueue<DownloadVideoInfo> invoke() {
            return new LinkedBlockingQueue<>();
        }
    }

    static {
        d dVar = d.f268a;
        f258b = d.f269b;
        f259c = LazyKt__LazyJVMKt.lazy(a.f265c);
        f260d = LazyKt__LazyJVMKt.lazy(b.f266c);
    }

    /* renamed from: a */
    public final void m185a(@NotNull DownloadVideoInfo downloadVideoInfo) {
        Intrinsics.checkNotNullParameter(downloadVideoInfo, "downloadVideoInfo");
        Intrinsics.stringPlus("addDownload: 下载长度：", Integer.valueOf(m188d().size()));
        if (m188d().size() <= 0) {
            RunnableC0860n runnableC0860n = new RunnableC0860n(downloadVideoInfo, new e(downloadVideoInfo));
            HashMap<String, RunnableC0860n> m188d = m188d();
            String str = downloadVideoInfo.f9947id;
            Intrinsics.checkNotNullExpressionValue(str, "downloadVideoInfo.id");
            m188d.put(str, runnableC0860n);
            C4909c m5569b = C4909c.m5569b();
            downloadVideoInfo.status = "doing";
            Unit unit = Unit.INSTANCE;
            m5569b.m5574g(new EventDownload(downloadVideoInfo));
            ((ExecutorService) this.f261e.getValue()).execute(runnableC0860n);
            return;
        }
        boolean z = false;
        Iterator<DownloadVideoInfo> it = m190f().iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            } else if (Intrinsics.areEqual(it.next().f9947id, downloadVideoInfo.f9947id)) {
                z = true;
                break;
            }
        }
        if (!z) {
            m190f().offer(downloadVideoInfo);
        }
        C4909c m5569b2 = C4909c.m5569b();
        downloadVideoInfo.status = "wait";
        Unit unit2 = Unit.INSTANCE;
        m5569b2.m5574g(new EventDownload(downloadVideoInfo));
    }

    /* renamed from: b */
    public final void m186b(File file) {
        if (!file.isDirectory()) {
            if (file.exists()) {
                file.delete();
                return;
            }
            return;
        }
        File[] files = file.listFiles();
        Intrinsics.checkNotNullExpressionValue(files, "files");
        int i2 = 0;
        int length = files.length;
        while (i2 < length) {
            File f2 = files[i2];
            i2++;
            Intrinsics.checkNotNullExpressionValue(f2, "f");
            m186b(f2);
        }
        file.delete();
    }

    /* renamed from: c */
    public final void m187c(@NotNull String... taskIds) {
        InterfaceC3053d1 interfaceC3053d1;
        Intrinsics.checkNotNullParameter(taskIds, "taskIds");
        int length = taskIds.length;
        int i2 = 0;
        while (i2 < length) {
            String str = taskIds[i2];
            i2++;
            RunnableC0860n remove = m188d().remove(str);
            if (remove != null && (interfaceC3053d1 = remove.f292h) != null && interfaceC3053d1.mo3507b()) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
            Iterator<DownloadVideoInfo> it = m190f().iterator();
            while (it.hasNext()) {
                DownloadVideoInfo next = it.next();
                if (Intrinsics.areEqual(next.f9947id, str)) {
                    m190f().remove(next);
                }
            }
            m186b(new File(C4195m.m4792Y().getExternalCacheDir(), str));
        }
    }

    /* renamed from: d */
    public final HashMap<String, RunnableC0860n> m188d() {
        return (HashMap) this.f263g.getValue();
    }

    @Nullable
    /* renamed from: e */
    public final DownloadVideoInfo m189e(@NotNull String taskId) {
        Intrinsics.checkNotNullParameter(taskId, "taskId");
        StringBuilder sb = new StringBuilder();
        sb.append(C4195m.m4792Y().getExternalCacheDir());
        String str = File.separator;
        sb.append((Object) str);
        sb.append(taskId);
        File file = new File(((Object) new File(sb.toString()).getPath()) + ((Object) str) + "info.json");
        if (!file.exists()) {
            return null;
        }
        BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
        String readText = TextStreamsKt.readText(bufferedReader);
        bufferedReader.close();
        DownloadVideoInfo downloadVideoInfo = (DownloadVideoInfo) JSON.parseObject(readText, DownloadVideoInfo.class);
        if (m188d().size() == 0) {
            downloadVideoInfo.status = Intrinsics.areEqual(downloadVideoInfo.status, "completed") ? "completed" : "error";
        }
        return downloadVideoInfo;
    }

    /* renamed from: f */
    public final LinkedBlockingQueue<DownloadVideoInfo> m190f() {
        return (LinkedBlockingQueue) this.f264h.getValue();
    }

    /* renamed from: g */
    public final boolean m191g(@NotNull String taskId) {
        Intrinsics.checkNotNullParameter(taskId, "taskId");
        Iterator<DownloadVideoInfo> it = m190f().iterator();
        while (it.hasNext()) {
            if (Intrinsics.areEqual(it.next().f9947id, taskId)) {
                return true;
            }
        }
        return false;
    }
}
