package p005b.p006a.p007a.p008a.p013o;

import com.jbzd.media.movecartoons.bean.response.GroupBean;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.o.c */
/* loaded from: classes2.dex */
public final class C0909c {

    /* renamed from: a */
    @NotNull
    public final List<GroupBean> f364a;

    /* renamed from: b */
    @NotNull
    public final List<GroupBean> f365b;

    /* renamed from: c */
    @NotNull
    public final String f366c;

    public C0909c(@NotNull List<GroupBean> baseVipGroup, @NotNull List<GroupBean> advancedGroup, @NotNull String tips) {
        Intrinsics.checkNotNullParameter(baseVipGroup, "baseVipGroup");
        Intrinsics.checkNotNullParameter(advancedGroup, "advancedGroup");
        Intrinsics.checkNotNullParameter(tips, "tips");
        this.f364a = baseVipGroup;
        this.f365b = advancedGroup;
        this.f366c = tips;
    }
}
