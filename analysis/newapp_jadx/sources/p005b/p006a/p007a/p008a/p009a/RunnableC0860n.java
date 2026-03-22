package p005b.p006a.p007a.p008a.p009a;

import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;

/* renamed from: b.a.a.a.a.n */
/* loaded from: classes2.dex */
public final class RunnableC0860n implements Runnable {

    /* renamed from: c */
    @NotNull
    public final DownloadVideoInfo f288c;

    /* renamed from: e */
    @NotNull
    public final Function1<DownloadVideoInfo, Unit> f289e;

    /* renamed from: f */
    @NotNull
    public final Lazy f290f;

    /* renamed from: g */
    @NotNull
    public final String f291g;

    /* renamed from: h */
    @Nullable
    public InterfaceC3053d1 f292h;

    /* renamed from: b.a.a.a.a.n$a */
    public static final class a extends Lambda implements Function0<String> {

        /* renamed from: c */
        public static final a f293c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public String invoke() {
            MyApp myApp = MyApp.f9891f;
            return MyApp.m4185f().cdn_header;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public RunnableC0860n(@NotNull DownloadVideoInfo downloadVideoInfo, @NotNull Function1<? super DownloadVideoInfo, Unit> success) {
        Intrinsics.checkNotNullParameter(downloadVideoInfo, "downloadVideoInfo");
        Intrinsics.checkNotNullParameter(success, "success");
        this.f288c = downloadVideoInfo;
        this.f289e = success;
        this.f290f = LazyKt__LazyJVMKt.lazy(a.f293c);
        this.f291g = "DownloadRunnable";
    }

    /* renamed from: a */
    public static final String m193a(RunnableC0860n runnableC0860n, String str) {
        Objects.requireNonNull(runnableC0860n);
        String substring = str.substring(StringsKt__StringsKt.lastIndexOf$default((CharSequence) str, "/", 0, false, 6, (Object) null) + 1);
        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String).substring(startIndex)");
        if (!StringsKt__StringsKt.contains$default((CharSequence) substring, (CharSequence) "?", false, 2, (Object) null)) {
            return substring;
        }
        String substring2 = substring.substring(0, StringsKt__StringsKt.indexOf$default((CharSequence) substring, "?", 0, false, 6, (Object) null));
        Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String…ing(startIndex, endIndex)");
        return substring2;
    }

    /* renamed from: b */
    public static final void m194b(RunnableC0860n runnableC0860n, String str, File file) {
        Objects.requireNonNull(runnableC0860n);
        try {
            if (file.exists()) {
                file.delete();
                file.createNewFile();
            } else {
                file.createNewFile();
            }
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file, false));
            bufferedWriter.write(str);
            bufferedWriter.close();
        } catch (Exception e2) {
            Intrinsics.stringPlus("错误:", e2);
        }
    }

    @Override // java.lang.Runnable
    public void run() {
        DownloadVideoInfo downloadVideoInfo = this.f288c;
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        this.f292h = C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new C0858m(downloadVideoInfo, this, null), 2, null);
    }
}
