package p005b.p006a.p007a.p008a.p009a;

import kotlin.jvm.internal.Intrinsics;
import me.jessyan.progressmanager.body.ProgressInfo;
import org.jetbrains.annotations.NotNull;
import p005b.p327w.p330b.p337d.C2859c;
import p448i.p449a.p450a.InterfaceC4348a;

/* renamed from: b.a.a.a.a.p */
/* loaded from: classes2.dex */
public final class C0866p implements InterfaceC4348a {

    /* renamed from: a */
    public final /* synthetic */ C2859c.c f302a;

    public C0866p(C2859c.c cVar) {
        this.f302a = cVar;
    }

    @Override // p448i.p449a.p450a.InterfaceC4348a
    /* renamed from: a */
    public void mo197a(long j2, @NotNull Exception e2) {
        Intrinsics.checkNotNullParameter(e2, "e");
        this.f302a.onDownloadFailed();
    }

    @Override // p448i.p449a.p450a.InterfaceC4348a
    /* renamed from: b */
    public void mo198b(@NotNull ProgressInfo progressInfo) {
        Intrinsics.checkNotNullParameter(progressInfo, "progressInfo");
        this.f302a.onDownloading(progressInfo);
    }
}
