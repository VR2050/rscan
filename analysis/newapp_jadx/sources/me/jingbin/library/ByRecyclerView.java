package me.jingbin.library;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import com.google.android.material.appbar.AppBarLayout;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import me.jingbin.library.adapter.BaseByRecyclerViewAdapter;
import me.jingbin.library.adapter.BaseByViewHolder;
import p448i.p452b.p453a.AbstractC4353a;
import p448i.p452b.p453a.InterfaceC4354b;
import p448i.p452b.p453a.InterfaceC4355c;
import p448i.p452b.p453a.RunnableC4357e;
import p448i.p452b.p453a.ViewOnClickListenerC4356d;
import p448i.p452b.p453a.ViewOnClickListenerC4358f;
import p448i.p452b.p453a.ViewOnLongClickListenerC4359g;

/* loaded from: classes3.dex */
public class ByRecyclerView extends RecyclerView {

    /* renamed from: c */
    public static final /* synthetic */ int f12638c = 0;

    /* renamed from: A */
    public InterfaceC4354b f12639A;

    /* renamed from: B */
    public InterfaceC4962i f12640B;

    /* renamed from: C */
    public InterfaceC4963j f12641C;

    /* renamed from: D */
    public InterfaceC4960g f12642D;

    /* renamed from: E */
    public InterfaceC4961h f12643E;

    /* renamed from: F */
    public AbstractC4353a.a f12644F;

    /* renamed from: G */
    public final RecyclerView.AdapterDataObserver f12645G;

    /* renamed from: H */
    public C4966m f12646H;

    /* renamed from: e */
    public ArrayList<Integer> f12647e;

    /* renamed from: f */
    public ArrayList<View> f12648f;

    /* renamed from: g */
    public FrameLayout f12649g;

    /* renamed from: h */
    public boolean f12650h;

    /* renamed from: i */
    public boolean f12651i;

    /* renamed from: j */
    public boolean f12652j;

    /* renamed from: k */
    public boolean f12653k;

    /* renamed from: l */
    public boolean f12654l;

    /* renamed from: m */
    public float f12655m;

    /* renamed from: n */
    public float f12656n;

    /* renamed from: o */
    public float f12657o;

    /* renamed from: p */
    public float f12658p;

    /* renamed from: q */
    public long f12659q;

    /* renamed from: r */
    public int f12660r;

    /* renamed from: s */
    public int f12661s;

    /* renamed from: t */
    public int f12662t;

    /* renamed from: u */
    public int f12663u;

    /* renamed from: v */
    public int f12664v;

    /* renamed from: w */
    public int f12665w;

    /* renamed from: x */
    public InterfaceC4965l f12666x;

    /* renamed from: y */
    public InterfaceC4355c f12667y;

    /* renamed from: z */
    public InterfaceC4964k f12668z;

    /* renamed from: me.jingbin.library.ByRecyclerView$a */
    public class RunnableC4954a implements Runnable {
        public RunnableC4954a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            InterfaceC4965l interfaceC4965l = ByRecyclerView.this.f12666x;
            if (interfaceC4965l != null) {
                interfaceC4965l.onRefresh();
            }
        }
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$b */
    public class C4955b extends GridLayoutManager.SpanSizeLookup {

        /* renamed from: a */
        public final /* synthetic */ GridLayoutManager f12670a;

        public C4955b(GridLayoutManager gridLayoutManager) {
            this.f12670a = gridLayoutManager;
        }

        @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
        public int getSpanSize(int i2) {
            if (!ByRecyclerView.this.m5621c(i2)) {
                Objects.requireNonNull(ByRecyclerView.this);
                if (!ByRecyclerView.this.m5622d(i2) && !ByRecyclerView.this.m5625g(i2) && !ByRecyclerView.this.m5624f(i2)) {
                    return 1;
                }
            }
            return this.f12670a.getSpanCount();
        }
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$c */
    public class RunnableC4956c implements Runnable {
        public RunnableC4956c() {
        }

        @Override // java.lang.Runnable
        public void run() {
            InterfaceC4964k interfaceC4964k = ByRecyclerView.this.f12668z;
            if (interfaceC4964k != null) {
                interfaceC4964k.m5628a();
            }
        }
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$d */
    public class RunnableC4957d implements Runnable {
        public RunnableC4957d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            InterfaceC4965l interfaceC4965l = ByRecyclerView.this.f12666x;
            if (interfaceC4965l != null) {
                interfaceC4965l.onRefresh();
            }
        }
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$e */
    public static class C4958e extends AbstractC4353a {

        /* renamed from: b */
        public WeakReference<ByRecyclerView> f12674b;

        public C4958e(ByRecyclerView byRecyclerView) {
            this.f12674b = new WeakReference<>(byRecyclerView);
        }

        @Override // p448i.p452b.p453a.AbstractC4353a
        /* renamed from: a */
        public void mo4928a(AppBarLayout appBarLayout, AbstractC4353a.a aVar) {
            if (this.f12674b.get() != null) {
                this.f12674b.get().setAppbarState(aVar);
            }
        }
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$g */
    public interface InterfaceC4960g {
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$h */
    public interface InterfaceC4961h {
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$i */
    public interface InterfaceC4962i {
        /* renamed from: a */
        void m5626a(View view, int i2);
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$j */
    public interface InterfaceC4963j {
        /* renamed from: a */
        boolean m5627a(View view, int i2);
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$k */
    public interface InterfaceC4964k {
        /* renamed from: a */
        void m5628a();
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$l */
    public interface InterfaceC4965l {
        void onRefresh();
    }

    public ByRecyclerView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public final boolean m5619a() {
        RecyclerView.LayoutManager layoutManager = getLayoutManager();
        if (layoutManager == null) {
            return false;
        }
        if (layoutManager instanceof LinearLayoutManager) {
            LinearLayoutManager linearLayoutManager = (LinearLayoutManager) layoutManager;
            return (linearLayoutManager.findLastCompletelyVisibleItemPosition() + 1 == this.f12646H.getItemCount() && linearLayoutManager.findFirstCompletelyVisibleItemPosition() == 0) ? false : true;
        }
        if (!(layoutManager instanceof StaggeredGridLayoutManager)) {
            return false;
        }
        StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
        int spanCount = staggeredGridLayoutManager.getSpanCount();
        int[] iArr = new int[spanCount];
        staggeredGridLayoutManager.findLastCompletelyVisibleItemPositions(iArr);
        int[] iArr2 = new int[staggeredGridLayoutManager.getSpanCount()];
        staggeredGridLayoutManager.findFirstCompletelyVisibleItemPositions(iArr2);
        int i2 = iArr[0];
        for (int i3 = 0; i3 < spanCount; i3++) {
            int i4 = iArr[i3];
            if (i4 > i2) {
                i2 = i4;
            }
        }
        return (i2 + 1 == this.f12646H.getItemCount() && iArr2[0] == 0) ? false : true;
    }

    /* renamed from: b */
    public final boolean m5620b(int i2) {
        return this.f12651i && getHeaderViewCount() > 0 && this.f12647e.contains(Integer.valueOf(i2));
    }

    /* renamed from: c */
    public boolean m5621c(int i2) {
        if (this.f12651i && i2 >= getPullHeaderSize()) {
            if (i2 < getPullHeaderSize() + getHeaderViewCount()) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: d */
    public boolean m5622d(int i2) {
        int i3;
        return (this.f12668z != null && ((i3 = this.f12665w) == 1 || i3 == 2)) && i2 == this.f12646H.getItemCount() - 1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0019, code lost:
    
        if (r0 != 3) goto L27;
     */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean dispatchTouchEvent(android.view.MotionEvent r5) {
        /*
            r4 = this;
            boolean r0 = r4.f12650h
            r1 = 1
            if (r0 == 0) goto L9
            int r0 = r4.f12663u
            if (r0 == 0) goto Ld
        L9:
            int r0 = r4.f12663u
            if (r0 != r1) goto L6e
        Ld:
            int r0 = r5.getAction()
            if (r0 == 0) goto L59
            if (r0 == r1) goto L51
            r2 = 2
            if (r0 == r2) goto L1c
            r2 = 3
            if (r0 == r2) goto L51
            goto L6e
        L1c:
            float r0 = r5.getX()
            int r0 = (int) r0
            float r2 = r5.getY()
            int r2 = (int) r2
            int r3 = r4.f12661s
            int r0 = r0 - r3
            int r0 = java.lang.Math.abs(r0)
            int r3 = r4.f12662t
            int r2 = r2 - r3
            int r2 = java.lang.Math.abs(r2)
            if (r0 <= r2) goto L43
            int r3 = r4.f12660r
            if (r0 <= r3) goto L43
            android.view.ViewParent r0 = r4.getParent()
            r1 = 0
            r0.requestDisallowInterceptTouchEvent(r1)
            goto L6e
        L43:
            if (r2 <= r0) goto L6e
            int r0 = r4.f12660r
            if (r2 <= r0) goto L6e
            android.view.ViewParent r0 = r4.getParent()
            r0.requestDisallowInterceptTouchEvent(r1)
            goto L6e
        L51:
            android.view.ViewParent r0 = r4.getParent()
            r0.requestDisallowInterceptTouchEvent(r1)
            goto L6e
        L59:
            float r0 = r5.getX()
            int r0 = (int) r0
            r4.f12661s = r0
            float r0 = r5.getY()
            int r0 = (int) r0
            r4.f12662t = r0
            android.view.ViewParent r0 = r4.getParent()
            r0.requestDisallowInterceptTouchEvent(r1)
        L6e:
            boolean r5 = super.dispatchTouchEvent(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: me.jingbin.library.ByRecyclerView.dispatchTouchEvent(android.view.MotionEvent):boolean");
    }

    /* renamed from: e */
    public final boolean m5623e() {
        Object obj = this.f12667y;
        return (obj == null || !(obj instanceof View) || ((View) obj).getParent() == null) ? false : true;
    }

    /* renamed from: f */
    public boolean m5624f(int i2) {
        return this.f12650h && this.f12666x != null && i2 == 0;
    }

    /* renamed from: g */
    public boolean m5625g(int i2) {
        if (this.f12653k && this.f12649g != null) {
            if (i2 == getPullHeaderSize() + getHeaderViewCount()) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public RecyclerView.Adapter getAdapter() {
        C4966m c4966m = this.f12646H;
        if (c4966m != null) {
            return c4966m.f12676a;
        }
        return null;
    }

    public int getCustomTopItemViewCount() {
        return getStateViewSize() + getPullHeaderSize() + getHeaderViewCount();
    }

    public int getFooterViewSize() {
        boolean z = this.f12652j;
        return 0;
    }

    public int getHeaderViewCount() {
        if (this.f12651i) {
            return this.f12648f.size();
        }
        return 0;
    }

    public int getLoadMoreSize() {
        int i2;
        return this.f12668z != null && ((i2 = this.f12665w) == 1 || i2 == 2) ? 1 : 0;
    }

    @Nullable
    public final InterfaceC4960g getOnItemChildClickListener() {
        return this.f12642D;
    }

    @Nullable
    public final InterfaceC4961h getOnItemChildLongClickListener() {
        return this.f12643E;
    }

    public int getPullHeaderSize() {
        return (!this.f12650h || this.f12666x == null) ? 0 : 1;
    }

    public int getStateViewSize() {
        FrameLayout frameLayout;
        return (!this.f12653k || (frameLayout = this.f12649g) == null || frameLayout.getChildCount() == 0) ? 0 : 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        AppBarLayout appBarLayout;
        super.onAttachedToWindow();
        ViewParent parent = getParent();
        while (parent != null && !(parent instanceof CoordinatorLayout)) {
            parent = parent.getParent();
        }
        if (parent != null) {
            CoordinatorLayout coordinatorLayout = (CoordinatorLayout) parent;
            int childCount = coordinatorLayout.getChildCount() - 1;
            while (true) {
                if (childCount < 0) {
                    appBarLayout = null;
                    break;
                }
                View childAt = coordinatorLayout.getChildAt(childCount);
                if (childAt instanceof AppBarLayout) {
                    appBarLayout = (AppBarLayout) childAt;
                    break;
                }
                childCount--;
            }
            if (appBarLayout != null) {
                appBarLayout.addOnOffsetChangedListener((AppBarLayout.OnOffsetChangedListener) new C4958e(this));
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void onScrollStateChanged(int i2) {
        InterfaceC4354b interfaceC4354b;
        RecyclerView.LayoutManager layoutManager;
        super.onScrollStateChanged(i2);
        if (i2 != 0 || this.f12668z == null) {
            return;
        }
        boolean z = true;
        if (this.f12665w != 1 || (interfaceC4354b = this.f12639A) == null || interfaceC4354b.getState() != 1 || (layoutManager = getLayoutManager()) == null) {
            return;
        }
        int i3 = -1;
        if (layoutManager instanceof LinearLayoutManager) {
            i3 = ((LinearLayoutManager) layoutManager).findLastVisibleItemPosition();
        } else if (layoutManager instanceof StaggeredGridLayoutManager) {
            StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
            int spanCount = staggeredGridLayoutManager.getSpanCount();
            int[] iArr = new int[spanCount];
            staggeredGridLayoutManager.findLastVisibleItemPositions(iArr);
            i3 = iArr[0];
            for (int i4 = 0; i4 < spanCount; i4++) {
                int i5 = iArr[i4];
                if (i5 > i3) {
                    i3 = i5;
                }
            }
        }
        if (layoutManager.getChildCount() <= 0 || i3 != this.f12646H.getItemCount() - 1) {
            return;
        }
        if (!m5619a() && !this.f12654l) {
            z = false;
        }
        if (z) {
            if (!this.f12650h || this.f12667y.getState() < 2) {
                this.f12654l = false;
                this.f12639A.setState(0);
                long j2 = this.f12659q;
                if (j2 <= 0) {
                    this.f12668z.m5628a();
                } else {
                    postDelayed(new RunnableC4956c(), j2);
                }
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        AbstractC4353a.a aVar = AbstractC4353a.a.EXPANDED;
        if (this.f12655m == -1.0f) {
            this.f12655m = motionEvent.getRawY();
        }
        if (this.f12656n == 0.0f) {
            float y = motionEvent.getY();
            this.f12656n = y;
            this.f12657o = y;
        }
        int action = motionEvent.getAction();
        if (action != 0) {
            if (action != 2) {
                boolean z = true;
                this.f12654l = this.f12665w == 1 && this.f12656n - motionEvent.getY() >= -10.0f && motionEvent.getY() - this.f12657o <= 150.0f;
                this.f12656n = 0.0f;
                this.f12655m = -1.0f;
                if (this.f12650h && m5623e() && this.f12644F == aVar && this.f12666x != null) {
                    SimpleRefreshHeaderView simpleRefreshHeaderView = (SimpleRefreshHeaderView) this.f12667y;
                    if (simpleRefreshHeaderView.getVisibleHeight() <= simpleRefreshHeaderView.f12713k || simpleRefreshHeaderView.f12712j >= 2) {
                        z = false;
                    } else {
                        simpleRefreshHeaderView.setState(2);
                    }
                    simpleRefreshHeaderView.m5632c(simpleRefreshHeaderView.f12712j == 2 ? simpleRefreshHeaderView.f12713k : 0);
                    if (z) {
                        postDelayed(new RunnableC4957d(), 300L);
                    }
                }
            } else {
                if (motionEvent.getY() < this.f12657o) {
                    this.f12657o = motionEvent.getY();
                }
                float rawY = motionEvent.getRawY() - this.f12655m;
                this.f12655m = motionEvent.getRawY();
                if (this.f12650h && this.f12666x != null && m5623e() && this.f12644F == aVar) {
                    ((SimpleRefreshHeaderView) this.f12667y).m5631b(rawY / this.f12658p);
                    if (this.f12667y.getVisibleHeight() > 0 && this.f12667y.getState() < 2) {
                        motionEvent.setAction(0);
                        super.onTouchEvent(motionEvent);
                        return false;
                    }
                }
            }
        } else {
            this.f12655m = motionEvent.getRawY();
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setAdapter(RecyclerView.Adapter adapter) {
        if (adapter instanceof BaseByRecyclerViewAdapter) {
            ((BaseByRecyclerViewAdapter) adapter).f12717a = this;
        }
        C4966m c4966m = new C4966m(adapter);
        this.f12646H = c4966m;
        super.setAdapter(c4966m);
        if (!adapter.hasObservers()) {
            adapter.registerAdapterDataObserver(this.f12645G);
        }
        this.f12645G.onChanged();
        setRefreshing(false);
    }

    public void setAppbarState(AbstractC4353a.a aVar) {
        this.f12644F = aVar;
    }

    public void setDispatchTouch(boolean z) {
        this.f12663u = z ? 1 : 2;
    }

    public void setDragRate(float f2) {
        if (f2 <= 0.5d) {
            return;
        }
        this.f12658p = f2;
    }

    public void setEmptyView(int i2) {
        setStateView(i2);
    }

    public void setEmptyViewEnabled(boolean z) {
        setStateViewEnabled(z);
    }

    public void setFootViewEnabled(boolean z) {
        this.f12652j = z;
    }

    public void setHeaderViewEnabled(boolean z) {
        this.f12651i = z;
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setLayoutManager(RecyclerView.LayoutManager layoutManager) {
        super.setLayoutManager(layoutManager);
        if (this.f12646H == null || !(layoutManager instanceof GridLayoutManager)) {
            return;
        }
        GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
        gridLayoutManager.setSpanSizeLookup(new C4955b(gridLayoutManager));
    }

    public void setLoadMoreEnabled(boolean z) {
        if (z) {
            int i2 = this.f12665w;
            if (i2 == 2 || i2 == 4) {
                this.f12665w = 2;
            } else {
                this.f12665w = 1;
            }
        } else {
            int i3 = this.f12665w;
            if (i3 == 4 || i3 == 2) {
                this.f12665w = 4;
            } else {
                this.f12665w = 3;
            }
        }
        if (z) {
            return;
        }
        this.f12639A.setState(1);
    }

    public void setLoadingMoreBottomHeight(float f2) {
        this.f12639A.setLoadingMoreBottomHeight(f2);
    }

    public void setLoadingMoreView(InterfaceC4354b interfaceC4354b) {
        this.f12639A = interfaceC4354b;
        interfaceC4354b.setState(1);
    }

    public void setOnItemChildClickListener(InterfaceC4960g interfaceC4960g) {
        this.f12642D = interfaceC4960g;
    }

    public void setOnItemChildLongClickListener(InterfaceC4961h interfaceC4961h) {
        this.f12643E = interfaceC4961h;
    }

    public void setOnItemClickListener(InterfaceC4962i interfaceC4962i) {
        this.f12640B = interfaceC4962i;
    }

    public void setOnItemLongClickListener(InterfaceC4963j interfaceC4963j) {
        this.f12641C = interfaceC4963j;
    }

    public void setOnLoadMoreListener(InterfaceC4964k interfaceC4964k) {
        int i2 = this.f12664v;
        this.f12665w = 1;
        setLoadMoreEnabled(true);
        setPreLoadNumber(i2);
        this.f12668z = interfaceC4964k;
        this.f12659q = 0L;
    }

    public void setOnRefreshListener(InterfaceC4965l interfaceC4965l) {
        setRefreshEnabled(true);
        this.f12666x = interfaceC4965l;
    }

    public void setPreLoadNumber(int i2) {
        if (i2 > 0) {
            this.f12664v = i2;
        }
    }

    public void setRefreshEnabled(boolean z) {
        this.f12650h = z;
        if (this.f12667y == null) {
            this.f12667y = new SimpleRefreshHeaderView(getContext());
        }
    }

    public void setRefreshHeaderView(InterfaceC4355c interfaceC4355c) {
        this.f12667y = interfaceC4355c;
    }

    public void setRefreshing(boolean z) {
        if (!z) {
            if (getPullHeaderSize() > 0) {
                SimpleRefreshHeaderView simpleRefreshHeaderView = (SimpleRefreshHeaderView) this.f12667y;
                simpleRefreshHeaderView.setState(3);
                simpleRefreshHeaderView.m5632c(0);
            }
            if (getLoadMoreSize() == 0) {
                return;
            }
            this.f12639A.setState(1);
            return;
        }
        if (getPullHeaderSize() == 0 || this.f12667y.getState() == 2) {
            return;
        }
        RecyclerView.LayoutManager layoutManager = getLayoutManager();
        if (layoutManager != null) {
            layoutManager.scrollToPosition(0);
        }
        this.f12667y.setState(2);
        if (this.f12666x != null) {
            postDelayed(new RunnableC4954a(), 300L);
        }
    }

    public void setStateView(View view) {
        boolean z;
        if (this.f12649g == null) {
            this.f12649g = new FrameLayout(view.getContext());
            RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -1);
            ViewGroup.LayoutParams layoutParams2 = view.getLayoutParams();
            if (layoutParams2 != null) {
                ((ViewGroup.MarginLayoutParams) layoutParams).width = layoutParams2.width;
                ((ViewGroup.MarginLayoutParams) layoutParams).height = layoutParams2.height;
            }
            this.f12649g.setLayoutParams(layoutParams);
            z = true;
        } else {
            z = false;
        }
        this.f12649g.removeAllViews();
        if (view.getParent() != null && (view.getParent() instanceof ViewGroup)) {
            ((ViewGroup) view.getParent()).removeView(view);
        }
        this.f12649g.addView(view);
        this.f12653k = true;
        if (z && getStateViewSize() == 1) {
            int pullHeaderSize = getPullHeaderSize() + getHeaderViewCount();
            C4966m c4966m = this.f12646H;
            if (c4966m != null) {
                c4966m.f12676a.notifyItemInserted(pullHeaderSize);
            }
        }
    }

    public void setStateViewEnabled(boolean z) {
        this.f12653k = z;
    }

    public ByRecyclerView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public void setEmptyView(View view) {
        setStateView(view);
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$f */
    public class C4959f extends RecyclerView.AdapterDataObserver {
        public C4959f(ViewOnClickListenerC4356d viewOnClickListenerC4356d) {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onChanged() {
            C4966m c4966m = ByRecyclerView.this.f12646H;
            if (c4966m != null) {
                c4966m.notifyDataSetChanged();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeChanged(int i2, int i3) {
            ByRecyclerView.this.f12646H.notifyItemRangeChanged(i2, i3);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeInserted(int i2, int i3) {
            ByRecyclerView.this.f12646H.notifyItemRangeInserted(i2, i3);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeMoved(int i2, int i3, int i4) {
            ByRecyclerView.this.f12646H.notifyItemMoved(i2, i3);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeRemoved(int i2, int i3) {
            ByRecyclerView.this.f12646H.notifyItemRangeRemoved(i2, i3);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeChanged(int i2, int i3, Object obj) {
            ByRecyclerView.this.f12646H.notifyItemRangeChanged(i2, i3, obj);
        }
    }

    public ByRecyclerView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f12647e = new ArrayList<>();
        this.f12648f = new ArrayList<>();
        this.f12650h = false;
        this.f12651i = false;
        this.f12652j = false;
        this.f12653k = true;
        this.f12654l = false;
        this.f12655m = -1.0f;
        this.f12656n = 0.0f;
        this.f12658p = 2.5f;
        this.f12659q = 0L;
        this.f12664v = 1;
        this.f12665w = 0;
        this.f12644F = AbstractC4353a.a.EXPANDED;
        this.f12645G = new C4959f(null);
        if (isInEditMode()) {
            return;
        }
        SimpleLoadMoreView simpleLoadMoreView = new SimpleLoadMoreView(getContext());
        this.f12639A = simpleLoadMoreView;
        simpleLoadMoreView.setState(1);
        this.f12660r = ViewConfiguration.get(getContext()).getScaledTouchSlop();
    }

    /* renamed from: me.jingbin.library.ByRecyclerView$m */
    public class C4966m extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

        /* renamed from: a */
        public RecyclerView.Adapter f12676a;

        /* renamed from: me.jingbin.library.ByRecyclerView$m$a */
        public class a extends GridLayoutManager.SpanSizeLookup {

            /* renamed from: a */
            public final /* synthetic */ GridLayoutManager f12678a;

            public a(GridLayoutManager gridLayoutManager) {
                this.f12678a = gridLayoutManager;
            }

            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int i2) {
                if (!ByRecyclerView.this.m5621c(i2)) {
                    Objects.requireNonNull(ByRecyclerView.this);
                    if (!ByRecyclerView.this.m5622d(i2) && !ByRecyclerView.this.m5625g(i2) && !ByRecyclerView.this.m5624f(i2)) {
                        return 1;
                    }
                }
                return this.f12678a.getSpanCount();
            }
        }

        /* renamed from: me.jingbin.library.ByRecyclerView$m$b */
        public class b extends BaseByViewHolder {
            public b(C4966m c4966m, View view) {
                super(view);
            }

            @Override // me.jingbin.library.adapter.BaseByViewHolder
            /* renamed from: a */
            public void mo5629a(BaseByViewHolder baseByViewHolder, Object obj, int i2) {
            }
        }

        public C4966m(RecyclerView.Adapter adapter) {
            this.f12676a = adapter;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (this.f12676a == null) {
                return ByRecyclerView.this.getStateViewSize() + ByRecyclerView.this.getLoadMoreSize() + ByRecyclerView.this.getFooterViewSize() + ByRecyclerView.this.getHeaderViewCount() + ByRecyclerView.this.getPullHeaderSize();
            }
            return this.f12676a.getItemCount() + ByRecyclerView.this.getStateViewSize() + ByRecyclerView.this.getLoadMoreSize() + ByRecyclerView.this.getFooterViewSize() + ByRecyclerView.this.getHeaderViewCount() + ByRecyclerView.this.getPullHeaderSize();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i2) {
            int customTopItemViewCount;
            if (this.f12676a == null || i2 < ByRecyclerView.this.getCustomTopItemViewCount() || (customTopItemViewCount = i2 - ByRecyclerView.this.getCustomTopItemViewCount()) >= this.f12676a.getItemCount()) {
                return -1L;
            }
            return this.f12676a.getItemId(customTopItemViewCount);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i2) {
            int customTopItemViewCount;
            C4966m c4966m;
            RecyclerView.Adapter adapter;
            List<T> list;
            if (ByRecyclerView.this.m5624f(i2)) {
                return 10000;
            }
            if (ByRecyclerView.this.m5621c(i2)) {
                return ByRecyclerView.this.f12647e.get(i2 - ByRecyclerView.this.getPullHeaderSize()).intValue();
            }
            Objects.requireNonNull(ByRecyclerView.this);
            if (ByRecyclerView.this.m5625g(i2)) {
                return 10002;
            }
            ByRecyclerView byRecyclerView = ByRecyclerView.this;
            boolean z = true;
            if ((byRecyclerView.f12668z != null && byRecyclerView.f12665w == 2 && byRecyclerView.f12639A.getState() == 1 && ((c4966m = byRecyclerView.f12646H) == null || (adapter = c4966m.f12676a) == null || (!(adapter instanceof BaseByRecyclerViewAdapter) ? ((((c4966m.getItemCount() - byRecyclerView.getPullHeaderSize()) - byRecyclerView.getHeaderViewCount()) - byRecyclerView.getFooterViewSize()) - byRecyclerView.getLoadMoreSize()) - byRecyclerView.getStateViewSize() == 0 : (list = ((BaseByRecyclerViewAdapter) adapter).f12718b) == 0 || list.size() == 0))) && i2 >= byRecyclerView.f12646H.getItemCount() - byRecyclerView.f12664v && (!byRecyclerView.f12650h || byRecyclerView.f12667y.getState() == 0)) {
                byRecyclerView.f12639A.setState(0);
                long j2 = byRecyclerView.f12659q;
                if (j2 <= 0) {
                    byRecyclerView.f12668z.m5628a();
                } else {
                    byRecyclerView.postDelayed(new RunnableC4357e(byRecyclerView), j2);
                }
            }
            if (ByRecyclerView.this.m5622d(i2)) {
                return 10001;
            }
            if (this.f12676a == null || (customTopItemViewCount = i2 - ByRecyclerView.this.getCustomTopItemViewCount()) >= this.f12676a.getItemCount()) {
                return 0;
            }
            int itemViewType = this.f12676a.getItemViewType(customTopItemViewCount);
            ByRecyclerView byRecyclerView2 = ByRecyclerView.this;
            Objects.requireNonNull(byRecyclerView2);
            if (itemViewType != 10000 && itemViewType != 10001 && itemViewType != 10002 && !byRecyclerView2.f12647e.contains(Integer.valueOf(itemViewType))) {
                z = false;
            }
            if (z) {
                throw new IllegalStateException("ByRecyclerView require itemViewType in adapter should be less than 10000 !");
            }
            return itemViewType;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onAttachedToRecyclerView(@NonNull RecyclerView recyclerView) {
            super.onAttachedToRecyclerView(recyclerView);
            RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
            if (layoutManager instanceof GridLayoutManager) {
                GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
                gridLayoutManager.setSpanSizeLookup(new a(gridLayoutManager));
            }
            this.f12676a.onAttachedToRecyclerView(recyclerView);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(@NonNull RecyclerView.ViewHolder viewHolder, int i2) {
            int customTopItemViewCount;
            if (ByRecyclerView.this.m5624f(i2) || ByRecyclerView.this.m5621c(i2) || ByRecyclerView.this.m5625g(i2)) {
                return;
            }
            Objects.requireNonNull(ByRecyclerView.this);
            if (this.f12676a == null || (customTopItemViewCount = i2 - ByRecyclerView.this.getCustomTopItemViewCount()) >= this.f12676a.getItemCount()) {
                return;
            }
            this.f12676a.onBindViewHolder(viewHolder, customTopItemViewCount);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        @NonNull
        public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup viewGroup, int i2) {
            ViewGroup viewGroup2;
            ViewGroup viewGroup3;
            if (i2 == 10000) {
                return new b(this, (View) ByRecyclerView.this.f12667y);
            }
            if (i2 == 10001) {
                return new b(this, (View) ByRecyclerView.this.f12639A);
            }
            ByRecyclerView byRecyclerView = ByRecyclerView.this;
            int i3 = ByRecyclerView.f12638c;
            if (byRecyclerView.m5620b(i2)) {
                ByRecyclerView byRecyclerView2 = ByRecyclerView.this;
                View view = byRecyclerView2.m5620b(i2) ? byRecyclerView2.f12648f.get(i2 - 10004) : null;
                if (view != null && view.getParent() != null && (view.getParent() instanceof ViewGroup) && (viewGroup3 = (ViewGroup) view.getParent()) != null) {
                    viewGroup3.removeView(view);
                }
                return new b(this, view);
            }
            if (i2 == 10002) {
                FrameLayout frameLayout = ByRecyclerView.this.f12649g;
                if (frameLayout != null && frameLayout.getParent() != null && (ByRecyclerView.this.f12649g.getParent() instanceof ViewGroup) && (viewGroup2 = (ViewGroup) ByRecyclerView.this.f12649g.getParent()) != null) {
                    viewGroup2.removeView(ByRecyclerView.this.f12649g);
                }
                return new b(this, ByRecyclerView.this.f12649g);
            }
            if (i2 == 10003) {
                Objects.requireNonNull(ByRecyclerView.this);
                Objects.requireNonNull(ByRecyclerView.this);
                return new b(this, null);
            }
            RecyclerView.ViewHolder onCreateViewHolder = this.f12676a.onCreateViewHolder(viewGroup, i2);
            ByRecyclerView byRecyclerView3 = ByRecyclerView.this;
            Objects.requireNonNull(byRecyclerView3);
            if (onCreateViewHolder != null) {
                View view2 = onCreateViewHolder.itemView;
                if (byRecyclerView3.f12640B != null) {
                    view2.setOnClickListener(new ViewOnClickListenerC4358f(byRecyclerView3, onCreateViewHolder));
                }
                if (byRecyclerView3.f12641C != null) {
                    view2.setOnLongClickListener(new ViewOnLongClickListenerC4359g(byRecyclerView3, onCreateViewHolder));
                }
            }
            return onCreateViewHolder;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onDetachedFromRecyclerView(@NonNull RecyclerView recyclerView) {
            this.f12676a.onDetachedFromRecyclerView(recyclerView);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public boolean onFailedToRecycleView(@NonNull RecyclerView.ViewHolder viewHolder) {
            return this.f12676a.onFailedToRecycleView(viewHolder);
        }

        /* JADX WARN: Code restructure failed: missing block: B:12:0x0045, code lost:
        
            if (r3.f12677b.m5625g(r4.getLayoutPosition()) == false) goto L15;
         */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onViewAttachedToWindow(@androidx.annotation.NonNull androidx.recyclerview.widget.RecyclerView.ViewHolder r4) {
            /*
                r3 = this;
                super.onViewAttachedToWindow(r4)
                android.view.View r0 = r4.itemView
                android.view.ViewGroup$LayoutParams r0 = r0.getLayoutParams()
                if (r0 == 0) goto L4d
                boolean r1 = r0 instanceof androidx.recyclerview.widget.StaggeredGridLayoutManager.LayoutParams
                if (r1 == 0) goto L4d
                me.jingbin.library.ByRecyclerView r1 = me.jingbin.library.ByRecyclerView.this
                int r2 = r4.getLayoutPosition()
                boolean r1 = r1.m5621c(r2)
                if (r1 != 0) goto L47
                me.jingbin.library.ByRecyclerView r1 = me.jingbin.library.ByRecyclerView.this
                r4.getLayoutPosition()
                java.util.Objects.requireNonNull(r1)
                me.jingbin.library.ByRecyclerView r1 = me.jingbin.library.ByRecyclerView.this
                int r2 = r4.getLayoutPosition()
                boolean r1 = r1.m5624f(r2)
                if (r1 != 0) goto L47
                me.jingbin.library.ByRecyclerView r1 = me.jingbin.library.ByRecyclerView.this
                int r2 = r4.getLayoutPosition()
                boolean r1 = r1.m5622d(r2)
                if (r1 != 0) goto L47
                me.jingbin.library.ByRecyclerView r1 = me.jingbin.library.ByRecyclerView.this
                int r2 = r4.getLayoutPosition()
                boolean r1 = r1.m5625g(r2)
                if (r1 == 0) goto L4d
            L47:
                androidx.recyclerview.widget.StaggeredGridLayoutManager$LayoutParams r0 = (androidx.recyclerview.widget.StaggeredGridLayoutManager.LayoutParams) r0
                r1 = 1
                r0.setFullSpan(r1)
            L4d:
                androidx.recyclerview.widget.RecyclerView$Adapter r0 = r3.f12676a
                r0.onViewAttachedToWindow(r4)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: me.jingbin.library.ByRecyclerView.C4966m.onViewAttachedToWindow(androidx.recyclerview.widget.RecyclerView$ViewHolder):void");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewDetachedFromWindow(@NonNull RecyclerView.ViewHolder viewHolder) {
            this.f12676a.onViewDetachedFromWindow(viewHolder);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(@NonNull RecyclerView.ViewHolder viewHolder) {
            this.f12676a.onViewRecycled(viewHolder);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void registerAdapterDataObserver(@NonNull RecyclerView.AdapterDataObserver adapterDataObserver) {
            this.f12676a.registerAdapterDataObserver(adapterDataObserver);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void unregisterAdapterDataObserver(@NonNull RecyclerView.AdapterDataObserver adapterDataObserver) {
            this.f12676a.unregisterAdapterDataObserver(adapterDataObserver);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(@NonNull RecyclerView.ViewHolder viewHolder, int i2, @NonNull List<Object> list) {
            int customTopItemViewCount;
            if (ByRecyclerView.this.m5621c(i2) || ByRecyclerView.this.m5624f(i2) || ByRecyclerView.this.m5625g(i2)) {
                return;
            }
            Objects.requireNonNull(ByRecyclerView.this);
            if (this.f12676a == null || (customTopItemViewCount = i2 - ByRecyclerView.this.getCustomTopItemViewCount()) >= this.f12676a.getItemCount()) {
                return;
            }
            if (list.isEmpty()) {
                this.f12676a.onBindViewHolder(viewHolder, customTopItemViewCount);
            } else {
                this.f12676a.onBindViewHolder(viewHolder, customTopItemViewCount, list);
            }
        }
    }

    public void setStateView(int i2) {
        setStateView(LayoutInflater.from(getContext()).inflate(i2, (ViewGroup) getParent(), false));
    }
}
