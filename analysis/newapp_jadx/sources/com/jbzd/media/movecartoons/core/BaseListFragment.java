package com.jbzd.media.movecartoons.core;

import android.os.Handler;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.IntRange;
import androidx.annotation.LayoutRes;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1303c;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1306f;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1308h;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008c\u0001\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0006\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0015\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u000b\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u0002B\u0007¢\u0006\u0004\b~\u0010\tJ\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ)\u0010\u000f\u001a\u0004\u0018\u00010\u000e2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\f\u001a\u00020\u00042\u0006\u0010\r\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u0011\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0004H'¢\u0006\u0004\b\u0017\u0010\u0006J\u001f\u0010\u001b\u001a\u00020\u00072\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00028\u0000H&¢\u0006\u0004\b\u001b\u0010\u001cJ-\u0010\u001f\u001a\u00020\u00072\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00028\u00002\f\u0010\u001e\u001a\b\u0012\u0004\u0012\u00020\u00030\u001dH\u0016¢\u0006\u0004\b\u001f\u0010 J3\u0010&\u001a\u00020\u00072\u0012\u0010\"\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00180!2\u0006\u0010$\u001a\u00020#2\u0006\u0010%\u001a\u00020\u0004H\u0016¢\u0006\u0004\b&\u0010'J3\u0010)\u001a\u00020(2\u0012\u0010\"\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00180!2\u0006\u0010$\u001a\u00020#2\u0006\u0010%\u001a\u00020\u0004H\u0016¢\u0006\u0004\b)\u0010*J\u000f\u0010+\u001a\u00020\u0007H\u0016¢\u0006\u0004\b+\u0010\tJ\u001b\u0010.\u001a\u00020\u00072\n\u0010-\u001a\u00020,\"\u00020\u0004H\u0016¢\u0006\u0004\b.\u0010/J\u001b\u00100\u001a\u00020\u00072\n\u0010-\u001a\u00020,\"\u00020\u0004H\u0016¢\u0006\u0004\b0\u0010/J3\u00101\u001a\u00020\u00072\u0012\u0010\"\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00180!2\u0006\u0010$\u001a\u00020#2\u0006\u0010%\u001a\u00020\u0004H\u0016¢\u0006\u0004\b1\u0010'J3\u00102\u001a\u00020(2\u0012\u0010\"\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00180!2\u0006\u0010$\u001a\u00020#2\u0006\u0010%\u001a\u00020\u0004H\u0016¢\u0006\u0004\b2\u0010*J\r\u00103\u001a\u00020\u0007¢\u0006\u0004\b3\u0010\tJ!\u00106\u001a\u00020\u00072\u0006\u00104\u001a\u00020\u00042\b\b\u0002\u00105\u001a\u00020(H\u0016¢\u0006\u0004\b6\u00107J\u0017\u00108\u001a\u00020\u00072\u0006\u00104\u001a\u00020\u0004H\u0016¢\u0006\u0004\b8\u00109J\u000f\u0010:\u001a\u00020\u0007H\u0016¢\u0006\u0004\b:\u0010\tJ\u000f\u0010;\u001a\u00020\u0007H\u0016¢\u0006\u0004\b;\u0010\tJ\u0011\u0010=\u001a\u0004\u0018\u00010<H&¢\u0006\u0004\b=\u0010>J\u001f\u0010@\u001a\u00020\u00072\u000e\u0010?\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u001dH\u0016¢\u0006\u0004\b@\u0010AJ!\u0010B\u001a\u00020\u00072\b\b\u0001\u0010%\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u0000H\u0016¢\u0006\u0004\bB\u0010CJ\u000f\u0010D\u001a\u00020\u0007H\u0016¢\u0006\u0004\bD\u0010\tJ\u000f\u0010E\u001a\u00020\u0007H\u0016¢\u0006\u0004\bE\u0010\tJ\u000f\u0010F\u001a\u00020\u0007H\u0016¢\u0006\u0004\bF\u0010\tJ\u000f\u0010G\u001a\u00020(H\u0016¢\u0006\u0004\bG\u0010HJ\u000f\u0010I\u001a\u00020(H\u0016¢\u0006\u0004\bI\u0010HJ\u000f\u0010J\u001a\u00020\u000eH\u0016¢\u0006\u0004\bJ\u0010KJ\u000f\u0010L\u001a\u00020#H\u0016¢\u0006\u0004\bL\u0010MJ\u000f\u0010N\u001a\u00020#H\u0016¢\u0006\u0004\bN\u0010MJ\u000f\u0010O\u001a\u00020(H\u0016¢\u0006\u0004\bO\u0010HJ\u000f\u0010P\u001a\u00020\u0004H\u0016¢\u0006\u0004\bP\u0010\u0006J\u000f\u0010Q\u001a\u00020\u0004H\u0016¢\u0006\u0004\bQ\u0010\u0006J\u000f\u0010R\u001a\u00020\u0004H\u0016¢\u0006\u0004\bR\u0010\u0006J\u000f\u0010S\u001a\u00020\u0004H\u0016¢\u0006\u0004\bS\u0010\u0006J\u000f\u0010T\u001a\u00020\u0007H\u0016¢\u0006\u0004\bT\u0010\tR\u001d\u0010Z\u001a\u00020U8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bV\u0010W\u001a\u0004\bX\u0010YR)\u0010\"\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00180!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b[\u0010W\u001a\u0004\b\\\u0010]R\"\u0010^\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b^\u0010_\u001a\u0004\b`\u0010\u0006\"\u0004\ba\u00109R\u001d\u0010f\u001a\u00020b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bc\u0010W\u001a\u0004\bd\u0010eR$\u0010g\u001a\u0004\u0018\u00010<8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bg\u0010h\u001a\u0004\bi\u0010>\"\u0004\bj\u0010kR$\u0010l\u001a\u0004\u0018\u00010\u00148\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bl\u0010m\u001a\u0004\bn\u0010\u0016\"\u0004\bo\u0010pR\"\u0010q\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bq\u0010_\u001a\u0004\br\u0010\u0006\"\u0004\bs\u00109R\u001d\u0010x\u001a\u00020t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u0010W\u001a\u0004\bv\u0010wR\"\u0010y\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\by\u0010z\u001a\u0004\b{\u0010K\"\u0004\b|\u0010}¨\u0006\u007f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/BaseListFragment;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "", "d", "IntegerDigits", "FractionDigits", "", "getPercentFormat", "(DII)Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemLayoutId", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "", "payloads", "bindConvert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;Ljava/util/List;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "", "onItemLongClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)Z", "registerItemChildEvent", "", "viewIds", "registerItemChildClick", "([I)V", "registerItemChildLongClick", "onItemChildClick", "onItemChildLongClick", "reset", "page", "isShowSwipeLoading", "initResetRequestFrom", "(IZ)V", "initRequestFrom", "(I)V", "refresh", "loadMore", "Lc/a/d1;", "request", "()Lc/a/d1;", "t", "didRequestComplete", "(Ljava/util/List;)V", "addData", "(ILjava/lang/Object;)V", "didRequestError", "showEmptyDataView", "showErrorView", "getRefreshEnable", "()Z", "getLoadMoreEnable", "getEmptyTips", "()Ljava/lang/String;", "getEmptyDataView", "()Landroid/view/View;", "getErrorView", "autoRefresh", "getLeftPadding", "getRightPadding", "getTopPadding", "getBottomPadding", "onDestroyView", "Landroid/view/ViewGroup;", "video_list_container$delegate", "Lkotlin/Lazy;", "getVideo_list_container", "()Landroid/view/ViewGroup;", "video_list_container", "adapter$delegate", "getAdapter", "()Lcom/chad/library/adapter/base/BaseQuickAdapter;", "firstPage", "I", "getFirstPage", "setFirstPage", "Landroidx/recyclerview/widget/RecyclerView;", "rv_content$delegate", "getRv_content", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_content", "loadJob", "Lc/a/d1;", "getLoadJob", "setLoadJob", "(Lc/a/d1;)V", "mItemDecoration", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getMItemDecoration", "setMItemDecoration", "(Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;)V", "currentPage", "getCurrentPage", "setCurrentPage", "Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "mSwipeLayout$delegate", "getMSwipeLayout", "()Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "mSwipeLayout", "pageSize", "Ljava/lang/String;", "getPageSize", "setPageSize", "(Ljava/lang/String;)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseListFragment<T> extends MyThemeFragment<Object> {

    @Nullable
    private InterfaceC3053d1 loadJob;

    @Nullable
    private RecyclerView.ItemDecoration mItemDecoration;
    private int currentPage = 1;

    @NotNull
    private String pageSize = "10";

    /* renamed from: video_list_container$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy video_list_container = LazyKt__LazyJVMKt.lazy(new C3624e(this));

    /* renamed from: rv_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_content = LazyKt__LazyJVMKt.lazy(new C3623d(this));

    /* renamed from: mSwipeLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mSwipeLayout = LazyKt__LazyJVMKt.lazy(new C3622c(this));

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new C3620a(this));
    private int firstPage = 1;

    /* renamed from: com.jbzd.media.movecartoons.core.BaseListFragment$a */
    public static final class C3620a extends Lambda implements Function0<BaseListFragment$adapter$2$1> {

        /* renamed from: c */
        public final /* synthetic */ BaseListFragment<T> f10034c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3620a(BaseListFragment<T> baseListFragment) {
            super(0);
            this.f10034c = baseListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public BaseListFragment$adapter$2$1 invoke() {
            C1318f loadMoreModule;
            BaseListFragment$adapter$2$1 baseListFragment$adapter$2$1 = new BaseListFragment$adapter$2$1(this.f10034c, this.f10034c.getItemLayoutId());
            final BaseListFragment<T> baseListFragment = this.f10034c;
            baseListFragment$adapter$2$1.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.n.d
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter adapter, View view, int i2) {
                    BaseListFragment this$0 = BaseListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    this$0.onItemClick(adapter, view, i2);
                }
            });
            baseListFragment$adapter$2$1.setOnItemLongClickListener(new InterfaceC1306f() { // from class: b.a.a.a.n.c
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1306f
                /* renamed from: a */
                public final boolean mo214a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseListFragment this$0 = BaseListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    return this$0.onItemLongClick(adapter, view, i2);
                }
            });
            baseListFragment$adapter$2$1.setOnItemChildClickListener(new InterfaceC1302b() { // from class: b.a.a.a.n.e
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b
                /* renamed from: a */
                public final void mo215a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseListFragment this$0 = BaseListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    this$0.onItemChildClick(adapter, view, i2);
                }
            });
            baseListFragment$adapter$2$1.setOnItemChildLongClickListener(new InterfaceC1303c() { // from class: b.a.a.a.n.b
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1303c
                /* renamed from: a */
                public final boolean mo213a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseListFragment this$0 = BaseListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    return this$0.onItemChildLongClick(adapter, view, i2);
                }
            });
            if (baseListFragment.getLoadMoreEnable() && (loadMoreModule = baseListFragment$adapter$2$1.getLoadMoreModule()) != null) {
                loadMoreModule.setOnLoadMoreListener(new InterfaceC1308h() { // from class: b.a.a.a.n.f
                    @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1308h
                    /* renamed from: a */
                    public final void mo216a() {
                        BaseListFragment this$0 = BaseListFragment.this;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        this$0.loadMore();
                    }
                });
                loadMoreModule.f1059h = true;
                loadMoreModule.f1058g = true;
                loadMoreModule.f1060i = true;
            }
            return baseListFragment$adapter$2$1;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseListFragment$b */
    public static final class C3621b extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ BaseListFragment<T> f10036c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3621b(BaseListFragment<T> baseListFragment) {
            super(1);
            this.f10036c = baseListFragment;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            View it = view;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10036c.getAdapter().setEmptyView(R.layout.loading_view);
            this.f10036c.refresh();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseListFragment$c */
    public static final class C3622c extends Lambda implements Function0<SwipeRefreshLayout> {

        /* renamed from: c */
        public final /* synthetic */ BaseListFragment<T> f10037c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3622c(BaseListFragment<T> baseListFragment) {
            super(0);
            this.f10037c = baseListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public SwipeRefreshLayout invoke() {
            View view = this.f10037c.getView();
            SwipeRefreshLayout swipeRefreshLayout = view == null ? null : (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
            Objects.requireNonNull(swipeRefreshLayout, "null cannot be cast to non-null type androidx.swiperefreshlayout.widget.SwipeRefreshLayout");
            return swipeRefreshLayout;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseListFragment$d */
    public static final class C3623d extends Lambda implements Function0<RecyclerView> {

        /* renamed from: c */
        public final /* synthetic */ BaseListFragment<T> f10038c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3623d(BaseListFragment<T> baseListFragment) {
            super(0);
            this.f10038c = baseListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public RecyclerView invoke() {
            View view = this.f10038c.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_content);
            Objects.requireNonNull(recyclerView, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
            return recyclerView;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseListFragment$e */
    public static final class C3624e extends Lambda implements Function0<ViewGroup> {

        /* renamed from: c */
        public final /* synthetic */ BaseListFragment<T> f10039c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3624e(BaseListFragment<T> baseListFragment) {
            super(0);
            this.f10039c = baseListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public ViewGroup invoke() {
            View view = this.f10039c.getView();
            ViewGroup viewGroup = view == null ? null : (ViewGroup) view.findViewById(R.id.video_list_container);
            Objects.requireNonNull(viewGroup, "null cannot be cast to non-null type android.view.ViewGroup");
            return viewGroup;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: addData$lambda-3, reason: not valid java name */
    public static final void m5736addData$lambda3(BaseListFragment this$0, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getRv_content().scrollToPosition(i2);
    }

    public static /* synthetic */ void initResetRequestFrom$default(BaseListFragment baseListFragment, int i2, boolean z, int i3, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: initResetRequestFrom");
        }
        if ((i3 & 2) != 0) {
            z = true;
        }
        baseListFragment.initResetRequestFrom(i2, z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5737initViews$lambda2$lambda1(BaseListFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.refresh();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public void addData(@IntRange(from = 0) final int position, T item) {
        getAdapter().addData(position, (int) item);
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.n.a
            @Override // java.lang.Runnable
            public final void run() {
                BaseListFragment.m5736addData$lambda3(BaseListFragment.this, position);
            }
        }, 300L);
    }

    public boolean autoRefresh() {
        return true;
    }

    public void bindConvert(@NotNull BaseViewHolder helper, T item, @NotNull List<? extends Object> payloads) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
    }

    public abstract void bindItem(@NotNull BaseViewHolder helper, T item);

    public void didRequestComplete(@Nullable List<? extends T> t) {
        View view = getView();
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout));
        if (swipeRefreshLayout != null) {
            swipeRefreshLayout.setRefreshing(false);
        }
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(true);
        }
        if (this.currentPage == 1) {
            if (t == null || t.isEmpty()) {
                getAdapter().setNewData(null);
                showEmptyDataView();
                return;
            } else {
                getAdapter().removeEmptyView();
                BaseQuickAdapter<T, BaseViewHolder> adapter = getAdapter();
                Objects.requireNonNull(t, "null cannot be cast to non-null type java.util.ArrayList<T of com.jbzd.media.movecartoons.core.BaseListFragment>");
                adapter.setNewData((ArrayList) t);
                return;
            }
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 != null) {
            loadMoreModule2.m330f();
        }
        if (!(t == null || t.isEmpty())) {
            getAdapter().addData((Collection) t);
            return;
        }
        C1318f loadMoreModule3 = getAdapter().getLoadMoreModule();
        if (loadMoreModule3 == null) {
            return;
        }
        C1318f.m324h(loadMoreModule3, false, 1, null);
    }

    public void didRequestError() {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(true);
        }
        if (this.currentPage == 1) {
            showErrorView();
            return;
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 == null) {
            return;
        }
        loadMoreModule2.m332i();
    }

    @NotNull
    public final BaseQuickAdapter<T, BaseViewHolder> getAdapter() {
        return (BaseQuickAdapter) this.adapter.getValue();
    }

    public int getBottomPadding() {
        return 0;
    }

    public final int getCurrentPage() {
        return this.currentPage;
    }

    @NotNull
    public View getEmptyDataView() {
        View inflate = getLayoutInflater().inflate(R.layout.empty_view, (ViewGroup) getRv_content(), false);
        Intrinsics.checkNotNullExpressionValue(inflate, "layoutInflater.inflate(R.layout.empty_view, rv_content, false)");
        View findViewById = inflate.findViewById(R.id.tv_empty_tips);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
        ((TextView) findViewById).setText(getEmptyTips());
        return inflate;
    }

    @NotNull
    public String getEmptyTips() {
        String string = getResources().getString(R.string.empty_no_data);
        Intrinsics.checkNotNullExpressionValue(string, "resources.getString(R.string.empty_no_data)");
        return string;
    }

    @NotNull
    public View getErrorView() {
        View errorView = getLayoutInflater().inflate(R.layout.error_view, (ViewGroup) getRv_content(), false);
        View findViewById = errorView.findViewById(R.id.txt_tips);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
        ((TextView) findViewById).setText("异常了...");
        View findViewById2 = errorView.findViewById(R.id.btn_retry);
        Objects.requireNonNull(findViewById2, "null cannot be cast to non-null type android.view.View");
        C2354n.m2374A(findViewById2, 0L, new C3621b(this), 1);
        Intrinsics.checkNotNullExpressionValue(errorView, "errorView");
        return errorView;
    }

    public final int getFirstPage() {
        return this.firstPage;
    }

    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        return null;
    }

    @LayoutRes
    public abstract int getItemLayoutId();

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_frag;
    }

    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext());
    }

    public int getLeftPadding() {
        return 0;
    }

    @Nullable
    public final InterfaceC3053d1 getLoadJob() {
        return this.loadJob;
    }

    public boolean getLoadMoreEnable() {
        return true;
    }

    @Nullable
    public final RecyclerView.ItemDecoration getMItemDecoration() {
        return this.mItemDecoration;
    }

    @NotNull
    public final SwipeRefreshLayout getMSwipeLayout() {
        return (SwipeRefreshLayout) this.mSwipeLayout.getValue();
    }

    @NotNull
    public final String getPageSize() {
        return this.pageSize;
    }

    @Nullable
    public String getPercentFormat(double d2, int IntegerDigits, int FractionDigits) {
        NumberFormat percentInstance = NumberFormat.getPercentInstance();
        Intrinsics.checkNotNullExpressionValue(percentInstance, "getPercentInstance()");
        percentInstance.setMaximumIntegerDigits(IntegerDigits);
        percentInstance.setMinimumFractionDigits(FractionDigits);
        return percentInstance.format(d2);
    }

    public boolean getRefreshEnable() {
        return true;
    }

    public int getRightPadding() {
        return 0;
    }

    @NotNull
    public final RecyclerView getRv_content() {
        return (RecyclerView) this.rv_content.getValue();
    }

    public int getTopPadding() {
        return 0;
    }

    @NotNull
    public final ViewGroup getVideo_list_container() {
        return (ViewGroup) this.video_list_container.getValue();
    }

    public void initRequestFrom(int page) {
        this.firstPage = page;
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(true);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(false);
        }
        this.currentPage = page;
        this.loadJob = request();
    }

    public void initResetRequestFrom(int page, boolean isShowSwipeLoading) {
        this.firstPage = page;
        getAdapter().setNewData(null);
        getAdapter().setEmptyView(R.layout.loading_view);
        View view = getView();
        ((SwipeRefreshLayout) (view != null ? view.findViewById(R$id.swipeLayout) : null)).setRefreshing(isShowSwipeLoading);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(false);
        }
        this.currentPage = page;
        this.loadJob = request();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        getRv_content().setPadding(getLeftPadding(), getTopPadding(), getRightPadding(), getBottomPadding());
        this.mItemDecoration = getItemDecoration();
        RecyclerView rv_content = getRv_content();
        rv_content.setLayoutManager(getLayoutManager());
        rv_content.setAdapter(getAdapter());
        if (getMItemDecoration() != null) {
            RecyclerView.ItemDecoration mItemDecoration = getMItemDecoration();
            Intrinsics.checkNotNull(mItemDecoration);
            rv_content.addItemDecoration(mItemDecoration);
        }
        registerItemChildEvent();
        View view = getView();
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout));
        swipeRefreshLayout.setColorSchemeColors(swipeRefreshLayout.getResources().getColor(R.color.color_gold_main));
        swipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() { // from class: b.a.a.a.n.g
            @Override // androidx.swiperefreshlayout.widget.SwipeRefreshLayout.OnRefreshListener
            public final void onRefresh() {
                BaseListFragment.m5737initViews$lambda2$lambda1(BaseListFragment.this);
            }
        });
        View view2 = getView();
        ((SwipeRefreshLayout) (view2 == null ? null : view2.findViewById(R$id.swipeLayout))).setEnabled(getRefreshEnable());
        if (autoRefresh()) {
            View view3 = getView();
            ((SwipeRefreshLayout) (view3 != null ? view3.findViewById(R$id.swipeLayout) : null)).setRefreshing(true);
            refresh();
        }
    }

    public void loadMore() {
        this.currentPage++;
        this.loadJob = request();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        cancelJob(this.loadJob);
    }

    public void onItemChildClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    public boolean onItemChildLongClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        return false;
    }

    public void onItemClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    public boolean onItemLongClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        return false;
    }

    public void refresh() {
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(false);
        }
        this.currentPage = this.firstPage;
        this.loadJob = request();
    }

    public void registerItemChildClick(@NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            getAdapter().addChildClickViewIds(i3);
        }
    }

    public void registerItemChildEvent() {
    }

    public void registerItemChildLongClick(@NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            getAdapter().addChildLongClickViewIds(i3);
        }
    }

    @Nullable
    public abstract InterfaceC3053d1 request();

    public final void reset() {
        getAdapter().setNewData(null);
        getAdapter().setEmptyView(R.layout.loading_view);
        refresh();
    }

    public final void setCurrentPage(int i2) {
        this.currentPage = i2;
    }

    public final void setFirstPage(int i2) {
        this.firstPage = i2;
    }

    public final void setLoadJob(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        this.loadJob = interfaceC3053d1;
    }

    public final void setMItemDecoration(@Nullable RecyclerView.ItemDecoration itemDecoration) {
        this.mItemDecoration = itemDecoration;
    }

    public final void setPageSize(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.pageSize = str;
    }

    public void showEmptyDataView() {
        getAdapter().setEmptyView(getEmptyDataView());
    }

    public void showErrorView() {
        getAdapter().setEmptyView(getErrorView());
    }
}
