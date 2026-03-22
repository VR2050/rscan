package com.drake.brv;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.drake.brv.listener.OnBindViewHolderListener;
import com.drake.statelayout.StateChangedHandler;
import com.drake.statelayout.StateConfig;
import com.drake.statelayout.StateLayout;
import com.drake.statelayout.Status;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.scwang.smart.refresh.layout.SmartRefreshLayout;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2872b;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2884e;
import p005b.p340x.p341a.p343b.p347c.p351d.C2887a;
import p005b.p340x.p341a.p343b.p347c.p353f.C2890a;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

@Metadata(m5310d1 = {"\u0000\u009e\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u000b\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010 \n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0015\n\u0002\b\u0007\b\u0016\u0018\u0000 \u008b\u00012\u00020\u00012\u00020\u0002:\u0002\u008b\u0001B\u000f\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0002\u0010\u0005B\u0019\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007¢\u0006\u0002\u0010\bJO\u0010[\u001a\u00020(2\u0010\u0010\\\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010^\u0018\u00010]2\n\b\u0002\u0010_\u001a\u0004\u0018\u00010`2\u000e\b\u0002\u0010a\u001a\b\u0012\u0004\u0012\u00020\u00140b2\u0019\b\u0002\u0010c\u001a\u0013\u0012\u0004\u0012\u00020`\u0012\u0004\u0012\u00020\u00140'¢\u0006\u0002\b)J\u001a\u0010d\u001a\u00020(2\b\b\u0002\u0010e\u001a\u00020\u00142\b\b\u0002\u0010c\u001a\u00020\u0014J \u0010f\u001a\u00020g2\u0006\u0010h\u001a\u00020\n2\u0006\u0010e\u001a\u00020\u00142\u0006\u0010i\u001a\u00020\u0014H\u0016J'\u0010j\u001a\u00020g2\u0006\u0010h\u001a\u00020\n2\u0006\u0010e\u001a\u00020\u00142\b\u0010i\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0002\u0010kJ\r\u0010l\u001a\u00020(H\u0000¢\u0006\u0002\bmJ\b\u0010n\u001a\u00020(H\u0002J\b\u0010o\u001a\u00020(H\u0014J'\u0010p\u001a\u00020\u00002\u001f\u0010q\u001a\u001b\u0012\u0004\u0012\u000205\u0012\u0006\u0012\u0004\u0018\u00010^\u0012\u0004\u0012\u00020(0r¢\u0006\u0002\b)J'\u0010s\u001a\u00020\u00002\u001f\u0010q\u001a\u001b\u0012\u0004\u0012\u000205\u0012\u0006\u0012\u0004\u0018\u00010^\u0012\u0004\u0012\u00020(0r¢\u0006\u0002\b)J'\u0010t\u001a\u00020\u00002\u001f\u0010q\u001a\u001b\u0012\u0004\u0012\u000205\u0012\u0006\u0012\u0004\u0018\u00010^\u0012\u0004\u0012\u00020(0r¢\u0006\u0002\b)J\b\u0010u\u001a\u00020(H\u0014J\u001f\u0010&\u001a\u00020\u00002\u0017\u0010q\u001a\u0013\u0012\u0004\u0012\u00020\u0000\u0012\u0004\u0012\u00020(0'¢\u0006\u0002\b)J\u0010\u0010&\u001a\u00020(2\u0006\u0010v\u001a\u00020gH\u0016J'\u0010w\u001a\u00020\u00002\u001f\u0010q\u001a\u001b\u0012\u0004\u0012\u000205\u0012\u0006\u0012\u0004\u0018\u00010^\u0012\u0004\u0012\u00020(0r¢\u0006\u0002\b)J\u001f\u0010*\u001a\u00020\u00002\u0017\u0010q\u001a\u0013\u0012\u0004\u0012\u00020\u0000\u0012\u0004\u0012\u00020(0'¢\u0006\u0002\b)J\u0010\u0010*\u001a\u00020(2\u0006\u0010v\u001a\u00020gH\u0016J\u0006\u0010x\u001a\u00020(J\u0012\u0010y\u001a\u00020(2\n\b\u0002\u0010z\u001a\u0004\u0018\u00010^J\b\u0010{\u001a\u00020(H\u0002J\u0010\u0010|\u001a\u00020g2\u0006\u0010}\u001a\u00020\u0014H\u0016J\u0010\u0010~\u001a\u00020g2\u0006\u0010}\u001a\u00020\u0014H\u0016J\u0010\u0010\u007f\u001a\u00020g2\u0006\u0010i\u001a\u00020\u0014H\u0016J\u0011\u0010\u0080\u0001\u001a\u00020\u00002\b\u0010\u0081\u0001\u001a\u00030\u0082\u0001J\u0017\u0010\u0083\u0001\u001a\u00020\u00002\u000e\b\u0001\u0010\u0084\u0001\u001a\u00030\u0085\u0001\"\u00020\nJ\u001d\u0010\u0086\u0001\u001a\u00020(2\b\b\u0002\u0010c\u001a\u00020\u00142\n\b\u0002\u0010z\u001a\u0004\u0018\u00010^J\u0013\u0010\u0087\u0001\u001a\u00020(2\n\b\u0002\u0010z\u001a\u0004\u0018\u00010^J\u001e\u0010\u0088\u0001\u001a\u00020(2\n\b\u0002\u0010z\u001a\u0004\u0018\u00010^2\t\b\u0002\u0010\u0089\u0001\u001a\u00020\u0014J\u001d\u0010\u008a\u0001\u001a\u00020(2\n\b\u0002\u0010z\u001a\u0004\u0018\u00010^2\b\b\u0002\u0010x\u001a\u00020\u0014J\u0006\u0010W\u001a\u00020\u0014R$\u0010\u000b\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\n@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR$\u0010\u0010\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\n@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\r\"\u0004\b\u0012\u0010\u000fR\u000e\u0010\u0013\u001a\u00020\u0014X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u0015\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0016\u0010\r\"\u0004\b\u0017\u0010\u000fR\u001a\u0010\u0018\u001a\u00020\u0014X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR$\u0010\u001d\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\n@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001e\u0010\r\"\u0004\b\u001f\u0010\u000fR\u001a\u0010 \u001a\u00020!X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%R!\u0010&\u001a\u0015\u0012\u0004\u0012\u00020\u0000\u0012\u0004\u0012\u00020(\u0018\u00010'¢\u0006\u0002\b)X\u0082\u000e¢\u0006\u0002\n\u0000R!\u0010*\u001a\u0015\u0012\u0004\u0012\u00020\u0000\u0012\u0004\u0012\u00020(\u0018\u00010'¢\u0006\u0002\b)X\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u0010+\u001a\u00020\nX\u0086\u000e¢\u0006\u0010\n\u0002\b.\u001a\u0004\b,\u0010\r\"\u0004\b-\u0010\u000fR\u000e\u0010/\u001a\u00020\u0014X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u00100\u001a\u00020\u0014X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u00101\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b2\u0010\r\"\u0004\b3\u0010\u000fR\u0010\u00104\u001a\u0004\u0018\u000105X\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u00106\u001a\u00020\u0014X\u0086\u000e¢\u0006\u0010\n\u0002\b9\u001a\u0004\b7\u0010\u001a\"\u0004\b8\u0010\u001cR\u001c\u0010:\u001a\u00020\u0014X\u0086\u000e¢\u0006\u0010\n\u0002\b=\u001a\u0004\b;\u0010\u001a\"\u0004\b<\u0010\u001cR\u001c\u0010>\u001a\u0004\u0018\u00010?X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b@\u0010A\"\u0004\bB\u0010CR\u000e\u0010D\u001a\u00020\u0014X\u0082\u000e¢\u0006\u0002\n\u0000R$\u0010F\u001a\u00020E2\u0006\u0010\t\u001a\u00020E8F@FX\u0086\u000e¢\u0006\f\u001a\u0004\bG\u0010H\"\u0004\bI\u0010JR$\u0010K\u001a\u00020\u00142\u0006\u0010\t\u001a\u00020\u0014@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bL\u0010\u001a\"\u0004\bM\u0010\u001cR\u001c\u0010N\u001a\u0004\u0018\u00010OX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bP\u0010Q\"\u0004\bR\u0010SR\u001a\u0010T\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bU\u0010\r\"\u0004\bV\u0010\u000fR\u000e\u0010W\u001a\u00020\u0014X\u0082\u000e¢\u0006\u0002\n\u0000R$\u0010X\u001a\u00020\u00142\u0006\u0010\t\u001a\u00020\u0014@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bY\u0010\u001a\"\u0004\bZ\u0010\u001c¨\u0006\u008c\u0001"}, m5311d2 = {"Lcom/drake/brv/PageRefreshLayout;", "Lcom/scwang/smart/refresh/layout/SmartRefreshLayout;", "Lcom/scwang/smart/refresh/layout/listener/OnRefreshLoadMoreListener;", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "attrs", "Landroid/util/AttributeSet;", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "value", "", "emptyLayout", "getEmptyLayout", "()I", "setEmptyLayout", "(I)V", "errorLayout", "getErrorLayout", "setErrorLayout", "finishInflate", "", "index", "getIndex", "setIndex", "loaded", "getLoaded", "()Z", "setLoaded", "(Z)V", "loadingLayout", "getLoadingLayout", "setLoadingLayout", "onBindViewHolderListener", "Lcom/drake/brv/listener/OnBindViewHolderListener;", "getOnBindViewHolderListener", "()Lcom/drake/brv/listener/OnBindViewHolderListener;", "setOnBindViewHolderListener", "(Lcom/drake/brv/listener/OnBindViewHolderListener;)V", "onLoadMore", "Lkotlin/Function1;", "", "Lkotlin/ExtensionFunctionType;", "onRefresh", "preloadIndex", "getPreloadIndex", "setPreloadIndex", "preloadIndex$1", "realEnableLoadMore", "realEnableRefresh", "recyclerViewId", "getRecyclerViewId", "setRecyclerViewId", "refreshContent", "Landroid/view/View;", "refreshEnableWhenEmpty", "getRefreshEnableWhenEmpty", "setRefreshEnableWhenEmpty", "refreshEnableWhenEmpty$1", "refreshEnableWhenError", "getRefreshEnableWhenError", "setRefreshEnableWhenError", "refreshEnableWhenError$1", "rv", "Landroidx/recyclerview/widget/RecyclerView;", "getRv", "()Landroidx/recyclerview/widget/RecyclerView;", "setRv", "(Landroidx/recyclerview/widget/RecyclerView;)V", "stateChanged", "Lcom/drake/statelayout/StateChangedHandler;", "stateChangedHandler", "getStateChangedHandler", "()Lcom/drake/statelayout/StateChangedHandler;", "setStateChangedHandler", "(Lcom/drake/statelayout/StateChangedHandler;)V", "stateEnabled", "getStateEnabled", "setStateEnabled", "stateLayout", "Lcom/drake/statelayout/StateLayout;", "getStateLayout", "()Lcom/drake/statelayout/StateLayout;", "setStateLayout", "(Lcom/drake/statelayout/StateLayout;)V", "stateLayoutId", "getStateLayoutId", "setStateLayoutId", "trigger", "upFetchEnabled", "getUpFetchEnabled", "setUpFetchEnabled", "addData", "data", "", "", "adapter", "Lcom/drake/brv/BindingAdapter;", "isEmpty", "Lkotlin/Function0;", "hasMore", "finish", FindBean.status_success, "finishLoadMore", "Lcom/scwang/smart/refresh/layout/api/RefreshLayout;", "delayed", "noMoreData", "finishRefresh", "(IZLjava/lang/Boolean;)Lcom/scwang/smart/refresh/layout/api/RefreshLayout;", "initialize", "initialize$brv_release", "initializeState", "onAttachedToWindow", "onContent", "block", "Lkotlin/Function2;", "onEmpty", "onError", "onFinishInflate", "refreshLayout", "onLoading", "refresh", "refreshing", "tag", "reverseContentView", "setEnableLoadMore", "enabled", "setEnableRefresh", "setNoMoreData", "setOnMultiStateListener", "onMultiStateListener", "Lcom/drake/brv/listener/OnMultiStateListener;", "setRetryIds", "ids", "", "showContent", "showEmpty", "showError", "force", "showLoading", "Companion", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class PageRefreshLayout extends SmartRefreshLayout implements InterfaceC2884e {

    /* renamed from: S0 */
    public static final /* synthetic */ int f8946S0 = 0;

    /* renamed from: T0 */
    public int f8947T0;

    /* renamed from: U0 */
    @Nullable
    public StateLayout f8948U0;

    /* renamed from: V0 */
    public int f8949V0;

    /* renamed from: W0 */
    @Nullable
    public RecyclerView f8950W0;

    /* renamed from: X0 */
    public int f8951X0;

    /* renamed from: Y0 */
    public boolean f8952Y0;

    /* renamed from: Z0 */
    @NotNull
    public OnBindViewHolderListener f8953Z0;

    /* renamed from: a1 */
    @Nullable
    public View f8954a1;

    /* renamed from: b1 */
    public boolean f8955b1;

    /* renamed from: c1 */
    public boolean f8956c1;

    /* renamed from: d1 */
    public boolean f8957d1;

    /* renamed from: e1 */
    @Nullable
    public Function1<? super PageRefreshLayout, Unit> f8958e1;

    /* renamed from: f1 */
    public int f8959f1;

    /* renamed from: g1 */
    public boolean f8960g1;

    /* renamed from: h1 */
    public boolean f8961h1;

    /* renamed from: i1 */
    public int f8962i1;

    /* renamed from: j1 */
    public int f8963j1;

    /* renamed from: k1 */
    public int f8964k1;

    /* renamed from: l1 */
    public boolean f8965l1;

    /* renamed from: m1 */
    public boolean f8966m1;

    @Metadata(m5310d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"<anonymous>", "", "invoke", "()Ljava/lang/Boolean;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.PageRefreshLayout$a */
    public static final class C3237a extends Lambda implements Function0<Boolean> {

        /* renamed from: c */
        public final /* synthetic */ List<Object> f8967c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3237a(List<? extends Object> list) {
            super(0);
            this.f8967c = list;
        }

        @Override // kotlin.jvm.functions.Function0
        public Boolean invoke() {
            List<Object> list = this.f8967c;
            return Boolean.valueOf(list == null || list.isEmpty());
        }
    }

    @Metadata(m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {"<anonymous>", "", "Lcom/drake/brv/BindingAdapter;", "invoke", "(Lcom/drake/brv/BindingAdapter;)Ljava/lang/Boolean;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.PageRefreshLayout$b */
    public static final class C3238b extends Lambda implements Function1<BindingAdapter, Boolean> {

        /* renamed from: c */
        public static final C3238b f8968c = new C3238b();

        public C3238b() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Boolean invoke(BindingAdapter bindingAdapter) {
            Intrinsics.checkNotNullParameter(bindingAdapter, "$this$null");
            return Boolean.TRUE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0012\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004H\n¢\u0006\u0002\b\u0005"}, m5311d2 = {"<anonymous>", "", "Lcom/drake/statelayout/StateLayout;", "it", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.PageRefreshLayout$c */
    public static final class C3239c extends Lambda implements Function2<StateLayout, Object, Unit> {
        public C3239c() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public Unit invoke(StateLayout stateLayout, Object obj) {
            StateLayout onRefresh = stateLayout;
            Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
            PageRefreshLayout pageRefreshLayout = PageRefreshLayout.this;
            if (pageRefreshLayout.f8957d1) {
                pageRefreshLayout.f10522I = false;
            }
            pageRefreshLayout.m4614s(EnumC2878b.Refreshing);
            PageRefreshLayout pageRefreshLayout2 = PageRefreshLayout.this;
            pageRefreshLayout2.mo3326a(pageRefreshLayout2);
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000)\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J,\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\n\u0010\b\u001a\u00060\tR\u00020\u00072\u0006\u0010\n\u001a\u00020\u000bH\u0016¨\u0006\f"}, m5311d2 = {"com/drake/brv/PageRefreshLayout$onBindViewHolderListener$1", "Lcom/drake/brv/listener/OnBindViewHolderListener;", "onBindViewHolder", "", "rv", "Landroidx/recyclerview/widget/RecyclerView;", "adapter", "Lcom/drake/brv/BindingAdapter;", "holder", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "position", "", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.PageRefreshLayout$d */
    public static final class C3240d implements OnBindViewHolderListener {
        public C3240d() {
        }

        @Override // com.drake.brv.listener.OnBindViewHolderListener
        /* renamed from: a */
        public void mo1206a(@NotNull RecyclerView rv, @NotNull BindingAdapter adapter, @NotNull BindingAdapter.BindingViewHolder holder, int i2) {
            Intrinsics.checkNotNullParameter(rv, "rv");
            Intrinsics.checkNotNullParameter(adapter, "adapter");
            Intrinsics.checkNotNullParameter(holder, "holder");
            PageRefreshLayout pageRefreshLayout = PageRefreshLayout.this;
            int i3 = PageRefreshLayout.f8946S0;
            if (!pageRefreshLayout.f10524J || pageRefreshLayout.f10550d0 || rv.getScrollState() == 0 || PageRefreshLayout.this.getF8959f1() == -1 || adapter.getItemCount() - PageRefreshLayout.this.getF8959f1() > i2) {
                return;
            }
            final PageRefreshLayout pageRefreshLayout2 = PageRefreshLayout.this;
            pageRefreshLayout2.post(new Runnable() { // from class: b.i.a.e
                @Override // java.lang.Runnable
                public final void run() {
                    PageRefreshLayout this$0 = PageRefreshLayout.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    if (this$0.getState() == EnumC2878b.None) {
                        EnumC2878b enumC2878b = EnumC2878b.Loading;
                        int i4 = PageRefreshLayout.f8946S0;
                        this$0.m4614s(enumC2878b);
                        this$0.mo3327b(this$0);
                    }
                }
            });
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0017\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H\u0016¨\u0006\u0006"}, m5311d2 = {"com/drake/brv/PageRefreshLayout$upFetchEnabled$1", "Lcom/scwang/smart/refresh/layout/simple/SimpleBoundaryDecider;", "canLoadMore", "", "content", "Landroid/view/View;", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.PageRefreshLayout$e */
    public static final class C3241e extends C2887a {
        @Override // p005b.p340x.p341a.p343b.p347c.p351d.C2887a, p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g
        /* renamed from: b */
        public boolean mo3330b(@Nullable View view) {
            return mo3329a(view);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public PageRefreshLayout(@NotNull Context context) {
        this(context, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* renamed from: B */
    public static /* synthetic */ void m3948B(PageRefreshLayout pageRefreshLayout, boolean z, boolean z2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        if ((i2 & 2) != 0) {
            z2 = true;
        }
        pageRefreshLayout.m3952A(z, z2);
    }

    /* renamed from: F */
    public static void m3949F(PageRefreshLayout pageRefreshLayout, Object obj, int i2, Object obj2) {
        StateLayout stateLayout;
        int i3 = i2 & 1;
        if (pageRefreshLayout.f8961h1 && (stateLayout = pageRefreshLayout.f8948U0) != null) {
            stateLayout.m3995h(Status.EMPTY, null);
        }
        m3948B(pageRefreshLayout, false, false, 1, null);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x001f, code lost:
    
        if ((r3 == null ? null : r3.getF9021g()) != com.drake.statelayout.Status.CONTENT) goto L16;
     */
    /* renamed from: G */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m3950G(com.drake.brv.PageRefreshLayout r1, java.lang.Object r2, boolean r3, int r4, java.lang.Object r5) {
        /*
            r2 = r4 & 1
            r2 = 2
            r4 = r4 & r2
            r5 = 0
            if (r4 == 0) goto L8
            r3 = 0
        L8:
            boolean r4 = r1.f8961h1
            r0 = 0
            if (r4 == 0) goto L2b
            if (r3 != 0) goto L21
            boolean r3 = r1.f8960g1
            if (r3 == 0) goto L21
            com.drake.statelayout.StateLayout r3 = r1.f8948U0
            if (r3 != 0) goto L19
            r3 = r0
            goto L1d
        L19:
            b.i.b.e r3 = r3.getF9021g()
        L1d:
            b.i.b.e r4 = com.drake.statelayout.Status.CONTENT
            if (r3 == r4) goto L2b
        L21:
            com.drake.statelayout.StateLayout r3 = r1.f8948U0
            if (r3 != 0) goto L26
            goto L2b
        L26:
            b.i.b.e r4 = com.drake.statelayout.Status.ERROR
            r3.m3995h(r4, r0)
        L2b:
            m3948B(r1, r5, r5, r2, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.PageRefreshLayout.m3950G(com.drake.brv.PageRefreshLayout, java.lang.Object, boolean, int, java.lang.Object):void");
    }

    /* renamed from: z */
    public static void m3951z(PageRefreshLayout pageRefreshLayout, List list, BindingAdapter bindingAdapter, Function0 function0, Function1 hasMore, int i2, Object obj) {
        StateLayout stateLayout;
        if ((i2 & 2) != 0) {
            bindingAdapter = null;
        }
        C3237a isEmpty = (i2 & 4) != 0 ? new C3237a(list) : null;
        if ((i2 & 8) != 0) {
            hasMore = C3238b.f8968c;
        }
        Objects.requireNonNull(pageRefreshLayout);
        Intrinsics.checkNotNullParameter(isEmpty, "isEmpty");
        Intrinsics.checkNotNullParameter(hasMore, "hasMore");
        View view = pageRefreshLayout.f8954a1;
        RecyclerView recyclerView = pageRefreshLayout.f8950W0;
        if (bindingAdapter == null) {
            if (recyclerView != null) {
                bindingAdapter = C4195m.m4793Z(recyclerView);
            } else {
                if (!(view instanceof RecyclerView)) {
                    throw new UnsupportedOperationException("Use parameter [adapter] on [addData] function or PageRefreshLayout direct wrap RecyclerView");
                }
                bindingAdapter = C4195m.m4793Z((RecyclerView) view);
            }
        }
        boolean z = pageRefreshLayout.getState() == EnumC2878b.Refreshing || pageRefreshLayout.f8947T0 == 1;
        if (z) {
            List<Object> list2 = bindingAdapter.f8920v;
            if (list2 == null) {
                bindingAdapter.m3939q(list);
            } else if (TypeIntrinsics.isMutableList(list2)) {
                int size = list2.size();
                list2.clear();
                bindingAdapter.f8923y.clear();
                if (list == null || list.isEmpty()) {
                    bindingAdapter.notifyItemRangeRemoved(bindingAdapter.m3929f(), size);
                } else {
                    BindingAdapter.m3923a(bindingAdapter, list, false, 0, 6, null);
                }
            }
            if (((Boolean) isEmpty.invoke()).booleanValue()) {
                m3949F(pageRefreshLayout, null, 1, null);
                return;
            }
        } else {
            BindingAdapter.m3923a(bindingAdapter, list, false, 0, 6, null);
        }
        boolean booleanValue = ((Boolean) hasMore.invoke(bindingAdapter)).booleanValue();
        pageRefreshLayout.f8947T0++;
        if (!z) {
            pageRefreshLayout.m3952A(true, booleanValue);
            return;
        }
        if (pageRefreshLayout.f8961h1 && (stateLayout = pageRefreshLayout.f8948U0) != null) {
            stateLayout.m3995h(Status.CONTENT, null);
            stateLayout.f9022h = true;
        }
        m3948B(pageRefreshLayout, false, booleanValue, 1, null);
    }

    /* renamed from: A */
    public final void m3952A(boolean z, boolean z2) {
        EnumC2878b state = getState();
        Intrinsics.checkNotNullExpressionValue(state, "state");
        if (z) {
            this.f8960g1 = true;
        }
        StateLayout stateLayout = this.f8948U0;
        if (this.f8957d1) {
            if (stateLayout == null) {
                this.f10522I = true;
            } else if ((stateLayout.getF9021g() != Status.EMPTY || this.f8965l1) && (stateLayout.getF9021g() != Status.ERROR || this.f8966m1)) {
                this.f10522I = true;
            } else {
                this.f10522I = false;
            }
        }
        if (state != EnumC2878b.Refreshing) {
            if (z2) {
                mo3956k(z ? Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.f10525J0))), IjkMediaCodecInfo.RANK_SECURE) << 16 : 0, z, false);
                return;
            } else {
                m4608l();
                return;
            }
        }
        if (!z2) {
            m4609n();
        } else if (z) {
            mo3957m(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.f10525J0))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, Boolean.FALSE);
        } else {
            mo3957m(0, false, null);
        }
    }

    /* renamed from: C */
    public final void m3953C() {
        StateLayout stateLayout;
        if (StateConfig.f2876b == -1 && this.f8963j1 == -1 && StateConfig.f2877c == -1 && this.f8962i1 == -1 && StateConfig.f2878d == -1 && this.f8964k1 == -1) {
            setStateEnabled(false);
            return;
        }
        if (this.f8948U0 == null) {
            int i2 = this.f8949V0;
            if (i2 == -1) {
                Context context = getContext();
                Intrinsics.checkNotNullExpressionValue(context, "context");
                stateLayout = new StateLayout(context, null, 0, 6);
                removeView(this.f8954a1);
                stateLayout.addView(this.f8954a1);
                View view = this.f8954a1;
                Intrinsics.checkNotNull(view);
                stateLayout.setContent(view);
                m4618x(stateLayout);
            } else {
                stateLayout = (StateLayout) findViewById(i2);
            }
            this.f8948U0 = stateLayout;
        }
        StateLayout stateLayout2 = this.f8948U0;
        if (stateLayout2 == null) {
            return;
        }
        stateLayout2.setEmptyLayout(getF8962i1());
        stateLayout2.setErrorLayout(getF8963j1());
        stateLayout2.setLoadingLayout(getF8964k1());
        C3239c block = new C3239c();
        Intrinsics.checkNotNullParameter(block, "block");
        stateLayout2.f9020f = block;
    }

    @NotNull
    /* renamed from: D */
    public final PageRefreshLayout m3954D(@NotNull Function1<? super PageRefreshLayout, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.f8958e1 = block;
        return this;
    }

    /* renamed from: E */
    public final void m3955E() {
        float f2 = this.f8952Y0 ? -1.0f : 1.0f;
        getLayout().setScaleY(f2);
        ((C2890a) this.f10513D0).f7903c.setScaleY(f2);
        InterfaceC2873c refreshFooter = getRefreshFooter();
        View view = refreshFooter == null ? null : refreshFooter.getView();
        if (view == null) {
            return;
        }
        view.setScaleY(f2);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2884e
    /* renamed from: a */
    public void mo3326a(@NotNull InterfaceC2876f refreshLayout) {
        Intrinsics.checkNotNullParameter(refreshLayout, "refreshLayout");
        mo3958v(false);
        if (this.f8956c1) {
            super.mo3322c(false);
        }
        this.f8947T0 = 1;
        Function1<? super PageRefreshLayout, Unit> function1 = this.f8958e1;
        if (function1 == null) {
            return;
        }
        function1.invoke(this);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2884e
    /* renamed from: b */
    public void mo3327b(@NotNull InterfaceC2876f refreshLayout) {
        Intrinsics.checkNotNullParameter(refreshLayout, "refreshLayout");
        Function1<? super PageRefreshLayout, Unit> function1 = this.f8958e1;
        if (function1 == null) {
            return;
        }
        function1.invoke(this);
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f
    @NotNull
    /* renamed from: c */
    public InterfaceC2876f mo3322c(boolean z) {
        this.f8956c1 = z;
        this.f10552f0 = true;
        this.f10524J = z;
        Intrinsics.checkNotNullExpressionValue(this, "super.setEnableLoadMore(enabled)");
        return this;
    }

    /* renamed from: getEmptyLayout, reason: from getter */
    public final int getF8962i1() {
        return this.f8962i1;
    }

    /* renamed from: getErrorLayout, reason: from getter */
    public final int getF8963j1() {
        return this.f8963j1;
    }

    /* renamed from: getIndex, reason: from getter */
    public final int getF8947T0() {
        return this.f8947T0;
    }

    /* renamed from: getLoaded, reason: from getter */
    public final boolean getF8960g1() {
        return this.f8960g1;
    }

    /* renamed from: getLoadingLayout, reason: from getter */
    public final int getF8964k1() {
        return this.f8964k1;
    }

    @NotNull
    /* renamed from: getOnBindViewHolderListener, reason: from getter */
    public final OnBindViewHolderListener getF8953Z0() {
        return this.f8953Z0;
    }

    /* renamed from: getPreloadIndex, reason: from getter */
    public final int getF8959f1() {
        return this.f8959f1;
    }

    /* renamed from: getRecyclerViewId, reason: from getter */
    public final int getF8951X0() {
        return this.f8951X0;
    }

    /* renamed from: getRefreshEnableWhenEmpty, reason: from getter */
    public final boolean getF8965l1() {
        return this.f8965l1;
    }

    /* renamed from: getRefreshEnableWhenError, reason: from getter */
    public final boolean getF8966m1() {
        return this.f8966m1;
    }

    @Nullable
    /* renamed from: getRv, reason: from getter */
    public final RecyclerView getF8950W0() {
        return this.f8950W0;
    }

    @NotNull
    public final StateChangedHandler getStateChangedHandler() {
        StateLayout stateLayout = this.f8948U0;
        Intrinsics.checkNotNull(stateLayout);
        return stateLayout.getF9024j();
    }

    /* renamed from: getStateEnabled, reason: from getter */
    public final boolean getF8961h1() {
        return this.f8961h1;
    }

    @Nullable
    /* renamed from: getStateLayout, reason: from getter */
    public final StateLayout getF8948U0() {
        return this.f8948U0;
    }

    /* renamed from: getStateLayoutId, reason: from getter */
    public final int getF8949V0() {
        return this.f8949V0;
    }

    /* renamed from: getUpFetchEnabled, reason: from getter */
    public final boolean getF8952Y0() {
        return this.f8952Y0;
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout
    @NotNull
    /* renamed from: k */
    public InterfaceC2876f mo3956k(int i2, boolean z, boolean z2) {
        super.mo3956k(i2, z, z2);
        if (this.f8956c1) {
            if (this.f8961h1) {
                StateLayout stateLayout = this.f8948U0;
                if ((stateLayout == null ? null : stateLayout.getF9021g()) != Status.CONTENT) {
                    super.mo3322c(false);
                }
            }
            super.mo3322c(true);
        }
        return this;
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout
    @NotNull
    /* renamed from: m */
    public InterfaceC2876f mo3957m(int i2, boolean z, @Nullable Boolean bool) {
        super.mo3957m(i2, z, bool);
        if (!this.f10546W) {
            boolean z2 = Intrinsics.areEqual(bool, Boolean.FALSE) || !this.f10550d0;
            this.f10546W = z2;
            InterfaceC2872b interfaceC2872b = this.f10513D0;
            if (interfaceC2872b != null) {
                ((C2890a) interfaceC2872b).f7911l.f7898c = z2;
            }
        }
        if (this.f8956c1) {
            if (this.f8961h1) {
                StateLayout stateLayout = this.f8948U0;
                if ((stateLayout == null ? null : stateLayout.getF9021g()) != Status.CONTENT) {
                    super.mo3322c(false);
                }
            }
            super.mo3322c(true);
        }
        return this;
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout, android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        m3955E();
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout, android.view.View
    public void onFinishInflate() {
        this.f8950W0 = (RecyclerView) findViewById(this.f8951X0);
        this.f10557i0 = this;
        this.f10559j0 = this;
        int i2 = 0;
        boolean z = this.f10524J || !this.f10552f0;
        this.f10524J = z;
        this.f8956c1 = z;
        this.f8957d1 = this.f10522I;
        if (this.f8954a1 == null) {
            int childCount = getChildCount();
            while (true) {
                if (i2 >= childCount) {
                    break;
                }
                int i3 = i2 + 1;
                View childAt = getChildAt(i2);
                if (!(childAt instanceof InterfaceC2871a)) {
                    this.f8954a1 = childAt;
                    break;
                }
                i2 = i3;
            }
            if (this.f8961h1) {
                m3953C();
            }
            final View view = this.f8950W0;
            if (view == null) {
                view = this.f8954a1;
            }
            if (view instanceof RecyclerView) {
                ((RecyclerView) view).addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: b.i.a.f
                    @Override // android.view.View.OnLayoutChangeListener
                    public final void onLayoutChange(View view2, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11) {
                        View view3 = view;
                        PageRefreshLayout this$0 = this;
                        int i12 = PageRefreshLayout.f8946S0;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        RecyclerView.Adapter adapter = ((RecyclerView) view3).getAdapter();
                        if (adapter instanceof BindingAdapter) {
                            ((BindingAdapter) adapter).f8902d.add(this$0.f8953Z0);
                        }
                    }
                });
            }
        }
        super.onFinishInflate();
        this.f8955b1 = true;
    }

    public final void setEmptyLayout(int i2) {
        this.f8962i1 = i2;
        StateLayout stateLayout = this.f8948U0;
        if (stateLayout == null) {
            return;
        }
        stateLayout.setEmptyLayout(i2);
    }

    public final void setErrorLayout(int i2) {
        this.f8963j1 = i2;
        StateLayout stateLayout = this.f8948U0;
        if (stateLayout == null) {
            return;
        }
        stateLayout.setErrorLayout(i2);
    }

    public final void setIndex(int i2) {
        this.f8947T0 = i2;
    }

    public final void setLoaded(boolean z) {
        this.f8960g1 = z;
    }

    public final void setLoadingLayout(int i2) {
        this.f8964k1 = i2;
        StateLayout stateLayout = this.f8948U0;
        if (stateLayout == null) {
            return;
        }
        stateLayout.setLoadingLayout(i2);
    }

    public final void setOnBindViewHolderListener(@NotNull OnBindViewHolderListener onBindViewHolderListener) {
        Intrinsics.checkNotNullParameter(onBindViewHolderListener, "<set-?>");
        this.f8953Z0 = onBindViewHolderListener;
    }

    public final void setPreloadIndex(int i2) {
        this.f8959f1 = i2;
    }

    public final void setRecyclerViewId(int i2) {
        this.f8951X0 = i2;
    }

    public final void setRefreshEnableWhenEmpty(boolean z) {
        this.f8965l1 = z;
    }

    public final void setRefreshEnableWhenError(boolean z) {
        this.f8966m1 = z;
    }

    public final void setRv(@Nullable RecyclerView recyclerView) {
        this.f8950W0 = recyclerView;
    }

    public final void setStateChangedHandler(@NotNull StateChangedHandler value) {
        Intrinsics.checkNotNullParameter(value, "value");
        StateLayout stateLayout = this.f8948U0;
        Intrinsics.checkNotNull(stateLayout);
        stateLayout.setStateChangedHandler(value);
    }

    public final void setStateEnabled(boolean z) {
        StateLayout stateLayout;
        this.f8961h1 = z;
        if (this.f8955b1) {
            if (z && this.f8948U0 == null) {
                m3953C();
            } else {
                if (z || (stateLayout = this.f8948U0) == null) {
                    return;
                }
                int i2 = StateLayout.f9018c;
                stateLayout.m3995h(Status.CONTENT, null);
                stateLayout.f9022h = true;
            }
        }
    }

    public final void setStateLayout(@Nullable StateLayout stateLayout) {
        this.f8948U0 = stateLayout;
    }

    public final void setStateLayoutId(int i2) {
        this.f8949V0 = i2;
    }

    public final void setUpFetchEnabled(boolean z) {
        if (z == this.f8952Y0) {
            return;
        }
        this.f8952Y0 = z;
        if (z) {
            this.f8957d1 = false;
            this.f10522I = false;
            Intrinsics.checkNotNullExpressionValue(this, "super.setEnableRefresh(enabled)");
            setNestedScrollingEnabled(false);
            this.f10542S = true;
            this.f10544U = true;
            C3241e c3241e = new C3241e();
            this.f10561k0 = c3241e;
            InterfaceC2872b interfaceC2872b = this.f10513D0;
            if (interfaceC2872b != null) {
                ((C2890a) interfaceC2872b).m3344f(c3241e);
            }
        } else {
            setNestedScrollingEnabled(false);
            C2887a c2887a = new C2887a();
            this.f10561k0 = c2887a;
            InterfaceC2872b interfaceC2872b2 = this.f10513D0;
            if (interfaceC2872b2 != null) {
                ((C2890a) interfaceC2872b2).m3344f(c2887a);
            }
        }
        if (this.f8955b1) {
            m3955E();
        }
    }

    @Override // com.scwang.smart.refresh.layout.SmartRefreshLayout
    @NotNull
    /* renamed from: v */
    public InterfaceC2876f mo3958v(boolean z) {
        if (this.f10511C0 != null && this.f10513D0 != null) {
            super.mo3958v(z);
        }
        return this;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PageRefreshLayout(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.f8947T0 = 1;
        this.f8949V0 = -1;
        this.f8951X0 = -1;
        this.f8953Z0 = new C3240d();
        this.f8959f1 = 3;
        this.f8961h1 = true;
        this.f8962i1 = -1;
        this.f8963j1 = -1;
        this.f8964k1 = -1;
        this.f8965l1 = true;
        this.f8966m1 = true;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.PageRefreshLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…leable.PageRefreshLayout)");
        try {
            setUpFetchEnabled(obtainStyledAttributes.getBoolean(R$styleable.PageRefreshLayout_page_upFetchEnabled, this.f8952Y0));
            setStateEnabled(obtainStyledAttributes.getBoolean(R$styleable.PageRefreshLayout_stateEnabled, this.f8961h1));
            this.f8949V0 = obtainStyledAttributes.getResourceId(R$styleable.PageRefreshLayout_page_state, this.f8949V0);
            this.f8951X0 = obtainStyledAttributes.getResourceId(R$styleable.PageRefreshLayout_page_rv, this.f8951X0);
            this.f10546W = false;
            this.f10546W = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableLoadMoreWhenContentNotFull, false);
            setEmptyLayout(obtainStyledAttributes.getResourceId(R$styleable.PageRefreshLayout_empty_layout, this.f8962i1));
            setErrorLayout(obtainStyledAttributes.getResourceId(R$styleable.PageRefreshLayout_error_layout, this.f8963j1));
            setLoadingLayout(obtainStyledAttributes.getResourceId(R$styleable.PageRefreshLayout_loading_layout, this.f8964k1));
        } finally {
            obtainStyledAttributes.recycle();
        }
    }
}
