package p005b.p067b.p068a.p069a.p070a.p078m;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import com.chad.library.adapter.base.BaseQuickAdapter;
import java.util.Objects;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1308h;
import p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a;
import p005b.p067b.p068a.p069a.p070a.p077l.EnumC1311b;

/* renamed from: b.b.a.a.a.m.f */
/* loaded from: classes.dex */
public class C1318f {

    /* renamed from: a */
    @NotNull
    public final BaseQuickAdapter<?, ?> f1052a;

    /* renamed from: b */
    @Nullable
    public InterfaceC1308h f1053b;

    /* renamed from: c */
    public boolean f1054c;

    /* renamed from: d */
    @NotNull
    public EnumC1311b f1055d;

    /* renamed from: e */
    public boolean f1056e;

    /* renamed from: f */
    @NotNull
    public AbstractC1310a f1057f;

    /* renamed from: g */
    public boolean f1058g;

    /* renamed from: h */
    public boolean f1059h;

    /* renamed from: i */
    public boolean f1060i;

    /* renamed from: j */
    public int f1061j;

    /* renamed from: k */
    public boolean f1062k;

    public C1318f(@NotNull BaseQuickAdapter<?, ?> baseQuickAdapter) {
        Intrinsics.checkNotNullParameter(baseQuickAdapter, "baseQuickAdapter");
        this.f1052a = baseQuickAdapter;
        this.f1054c = true;
        this.f1055d = EnumC1311b.Complete;
        this.f1057f = C1321i.f1065a;
        this.f1059h = true;
        this.f1060i = true;
        this.f1061j = 1;
    }

    /* renamed from: h */
    public static /* synthetic */ void m324h(C1318f c1318f, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        c1318f.m331g(z);
    }

    /* renamed from: a */
    public final void m325a(int i2) {
        EnumC1311b enumC1311b;
        if (this.f1059h && m328d() && i2 >= this.f1052a.getItemCount() - this.f1061j && (enumC1311b = this.f1055d) == EnumC1311b.Complete && enumC1311b != EnumC1311b.Loading && this.f1054c) {
            m329e();
        }
    }

    /* renamed from: b */
    public final void m326b() {
        final RecyclerView.LayoutManager layoutManager;
        if (this.f1060i) {
            return;
        }
        this.f1054c = false;
        RecyclerView recyclerView = this.f1052a.getWeakRecyclerView().get();
        if (recyclerView == null || (layoutManager = recyclerView.getLayoutManager()) == null) {
            return;
        }
        if (layoutManager instanceof LinearLayoutManager) {
            recyclerView.postDelayed(new Runnable() { // from class: b.b.a.a.a.m.b
                @Override // java.lang.Runnable
                public final void run() {
                    C1318f this$0 = C1318f.this;
                    RecyclerView.LayoutManager manager = layoutManager;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(manager, "$manager");
                    LinearLayoutManager linearLayoutManager = (LinearLayoutManager) manager;
                    Objects.requireNonNull(this$0);
                    if ((linearLayoutManager.findLastCompletelyVisibleItemPosition() + 1 == this$0.f1052a.getItemCount() && linearLayoutManager.findFirstCompletelyVisibleItemPosition() == 0) ? false : true) {
                        this$0.f1054c = true;
                    }
                }
            }, 50L);
        } else if (layoutManager instanceof StaggeredGridLayoutManager) {
            recyclerView.postDelayed(new Runnable() { // from class: b.b.a.a.a.m.a
                @Override // java.lang.Runnable
                public final void run() {
                    RecyclerView.LayoutManager manager = RecyclerView.LayoutManager.this;
                    C1318f this$0 = this;
                    Intrinsics.checkNotNullParameter(manager, "$manager");
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) manager;
                    int spanCount = staggeredGridLayoutManager.getSpanCount();
                    int[] iArr = new int[spanCount];
                    staggeredGridLayoutManager.findLastCompletelyVisibleItemPositions(iArr);
                    Objects.requireNonNull(this$0);
                    int i2 = -1;
                    int i3 = 0;
                    if (!(spanCount == 0)) {
                        while (i3 < spanCount) {
                            int i4 = iArr[i3];
                            i3++;
                            if (i4 > i2) {
                                i2 = i4;
                            }
                        }
                    }
                    if (i2 + 1 != this$0.f1052a.getItemCount()) {
                        this$0.f1054c = true;
                    }
                }
            }, 50L);
        }
    }

    /* renamed from: c */
    public final int m327c() {
        if (this.f1052a.hasEmptyView()) {
            return -1;
        }
        BaseQuickAdapter<?, ?> baseQuickAdapter = this.f1052a;
        return baseQuickAdapter.getFooterLayoutCount() + baseQuickAdapter.getData().size() + baseQuickAdapter.getHeaderLayoutCount();
    }

    /* renamed from: d */
    public final boolean m328d() {
        if (this.f1053b == null || !this.f1062k) {
            return false;
        }
        if (this.f1055d == EnumC1311b.End && this.f1056e) {
            return false;
        }
        return !this.f1052a.getData().isEmpty();
    }

    /* renamed from: e */
    public final void m329e() {
        InterfaceC1308h interfaceC1308h;
        this.f1055d = EnumC1311b.Loading;
        RecyclerView recyclerView = this.f1052a.getWeakRecyclerView().get();
        if ((recyclerView == null ? null : Boolean.valueOf(recyclerView.postDelayed(new Runnable() { // from class: b.b.a.a.a.m.c
            @Override // java.lang.Runnable
            public final void run() {
                C1318f this$0 = C1318f.this;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                InterfaceC1308h interfaceC1308h2 = this$0.f1053b;
                if (interfaceC1308h2 == null) {
                    return;
                }
                interfaceC1308h2.mo216a();
            }
        }, 500L))) != null || (interfaceC1308h = this.f1053b) == null) {
            return;
        }
        interfaceC1308h.mo216a();
    }

    /* renamed from: f */
    public final void m330f() {
        if (m328d()) {
            this.f1055d = EnumC1311b.Complete;
            this.f1052a.notifyItemChanged(m327c());
            m326b();
        }
    }

    @JvmOverloads
    /* renamed from: g */
    public final void m331g(boolean z) {
        if (m328d()) {
            this.f1056e = z;
            this.f1055d = EnumC1311b.End;
            if (z) {
                this.f1052a.notifyItemRemoved(m327c());
            } else {
                this.f1052a.notifyItemChanged(m327c());
            }
        }
    }

    /* renamed from: i */
    public final void m332i() {
        if (m328d()) {
            this.f1055d = EnumC1311b.Fail;
            this.f1052a.notifyItemChanged(m327c());
        }
    }

    /* renamed from: j */
    public final void m333j() {
        EnumC1311b enumC1311b = this.f1055d;
        EnumC1311b enumC1311b2 = EnumC1311b.Loading;
        if (enumC1311b == enumC1311b2) {
            return;
        }
        this.f1055d = enumC1311b2;
        this.f1052a.notifyItemChanged(m327c());
        m329e();
    }

    /* renamed from: k */
    public final void m334k(boolean z) {
        boolean m328d = m328d();
        this.f1062k = z;
        boolean m328d2 = m328d();
        if (m328d) {
            if (m328d2) {
                return;
            }
            this.f1052a.notifyItemRemoved(m327c());
        } else if (m328d2) {
            this.f1055d = EnumC1311b.Complete;
            this.f1052a.notifyItemInserted(m327c());
        }
    }

    public void setOnLoadMoreListener(@Nullable InterfaceC1308h interfaceC1308h) {
        this.f1053b = interfaceC1308h;
        m334k(true);
    }
}
