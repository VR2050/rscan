package im.uwrkaxlmjj.ui.hui.adapter.pageAdapter;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class PageAdapterHelper<T, VH extends RecyclerView.ViewHolder> implements MryEmptyView.OnEmptyOrErrorClickListener, Constants {
    public static int VIEW_TYPE_LOADING_MORE = 106320418;
    private boolean ignorePageLimit;
    private RecyclerView.Adapter mAdapter;
    private AdapterStateView mAdapterStateView;
    private WeakReference<Context> mContextWeak;
    private List<T> mData;
    private MryEmptyView mEmptyView;
    private boolean mIsRefreshing;
    private int mLastVisibleItem;
    private boolean mNoMoreData;
    private MryEmptyView.OnEmptyOrErrorClickListener mOnEmptyOrErrorClickListener;
    private RecyclerView mRv;
    private RefreshLayout refreshLayout;
    private GridLayoutManager.SpanSizeLookup spanSizeLookup;
    public int PAGE_LIMIT = 20;
    private int mStartPage = 1;
    private int mPage = 1;
    private RecyclerView.OnScrollListener mScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageAdapterHelper.1
        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView rv, int newState) {
            super.onScrollStateChanged(rv, newState);
            if (PageAdapterHelper.this.mShowLoadViewEnable && !PageAdapterHelper.this.mIsRefreshing && PageAdapterHelper.this.mLastVisibleItem != -1) {
                int totalCount = PageAdapterHelper.this.getItemCount() - 1;
                if ((totalCount >= PageAdapterHelper.this.PAGE_LIMIT || PageAdapterHelper.this.ignorePageLimit) && newState == 0 && PageAdapterHelper.this.mLastVisibleItem == totalCount && !PageAdapterHelper.this.mNoMoreData) {
                    PageAdapterHelper.this.mPage++;
                    PageAdapterHelper.this.loadData();
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView rv, int dx, int dy) {
            super.onScrolled(rv, dx, dy);
            if (PageAdapterHelper.this.mShowLoadViewEnable && !PageAdapterHelper.this.mIsRefreshing) {
                RecyclerView.LayoutManager layoutManager = rv.getLayoutManager();
                if (layoutManager instanceof LinearLayoutManager) {
                    PageAdapterHelper.this.mLastVisibleItem = ((LinearLayoutManager) layoutManager).findLastCompletelyVisibleItemPosition();
                }
            }
        }
    };
    private RecyclerView.AdapterDataObserver dataObserver = new RecyclerView.AdapterDataObserver() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageAdapterHelper.2
        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onChanged() {
            super.onChanged();
            PageAdapterHelper.this.checkIfEmpty();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeRemoved(int positionStart, int itemCount) {
            super.onItemRangeRemoved(positionStart, itemCount);
            PageAdapterHelper.this.checkIfEmpty();
        }
    };
    private boolean mShowLoadViewEnable = true;
    private ArrayList<PageLoadMoreListener> pageLoadMoreListenerList = new ArrayList<>();

    public void destroy() {
        RecyclerView.AdapterDataObserver adapterDataObserver;
        RecyclerView.OnScrollListener onScrollListener;
        RecyclerView recyclerView = this.mRv;
        if (recyclerView != null && (onScrollListener = this.mScrollListener) != null) {
            recyclerView.removeOnScrollListener(onScrollListener);
        }
        this.mScrollListener = null;
        this.mRv = null;
        RecyclerView.Adapter adapter = this.mAdapter;
        if (adapter != null && (adapterDataObserver = this.dataObserver) != null) {
            adapter.unregisterAdapterDataObserver(adapterDataObserver);
        }
        this.dataObserver = null;
        this.mAdapter = null;
        this.mEmptyView = null;
        this.mData = null;
        this.mAdapterStateView = null;
        this.pageLoadMoreListenerList = null;
        this.mOnEmptyOrErrorClickListener = null;
        this.mContextWeak = null;
    }

    public PageAdapterHelper(Context context, RecyclerView.Adapter adapter) {
        this.mContextWeak = new WeakReference<>(context);
        this.mAdapter = adapter;
        setAdapterStateView(new AdapterLoadMoreView(context));
        this.mAdapter.registerAdapterDataObserver(this.dataObserver);
        if (this.mEmptyView == null) {
            MryEmptyView mryEmptyView = new MryEmptyView(context);
            this.mEmptyView = mryEmptyView;
            mryEmptyView.setOnEmptyClickListener(this);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
    public boolean onEmptyViewButtonClick(boolean isEmptyButton) {
        MryEmptyView.OnEmptyOrErrorClickListener onEmptyOrErrorClickListener = this.mOnEmptyOrErrorClickListener;
        if (onEmptyOrErrorClickListener != null) {
            boolean tag = onEmptyOrErrorClickListener.onEmptyViewButtonClick(isEmptyButton);
            if (!tag) {
                loadData();
                return false;
            }
            return false;
        }
        loadData();
        return false;
    }

    public VH onCreateViewHolder(ViewGroup parent, int viewType) {
        if (this.mShowLoadViewEnable && !this.mIsRefreshing && viewType == VIEW_TYPE_LOADING_MORE) {
            AdapterStateView adapterStateView = this.mAdapterStateView;
            if (adapterStateView != null) {
                View view = adapterStateView.getView();
                return new PageHolder(view, 0);
            }
            return new PageHolder(parent);
        }
        return null;
    }

    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        if (this.mShowLoadViewEnable && !this.mIsRefreshing && holder.getItemViewType() == VIEW_TYPE_LOADING_MORE) {
            return true;
        }
        return false;
    }

    public boolean onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        if (this.mShowLoadViewEnable && !this.mIsRefreshing && holder.getItemViewType() == VIEW_TYPE_LOADING_MORE) {
            AdapterStateView adapterStateView = this.mAdapterStateView;
            if (adapterStateView != null) {
                adapterStateView.show();
                return true;
            }
            return true;
        }
        return false;
    }

    public int getItemViewType(int position) {
        if (!this.mShowLoadViewEnable || this.mIsRefreshing) {
            return -1;
        }
        if ((getItemCount() >= this.PAGE_LIMIT || this.ignorePageLimit) && position == getItemCount() - 1) {
            return VIEW_TYPE_LOADING_MORE;
        }
        return -1;
    }

    public int getItemCount() {
        int count = getData().size();
        if (hasLoadMoreCountInItemCount()) {
            return count + 1;
        }
        return count;
    }

    public boolean hasLoadMoreCountInItemCount() {
        return this.mShowLoadViewEnable && !this.mIsRefreshing && (getData().size() >= this.PAGE_LIMIT || this.ignorePageLimit);
    }

    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.mRv;
        if (recyclerView2 != null) {
            recyclerView2.removeOnScrollListener(this.mScrollListener);
        }
        this.mRv = recyclerView;
        recyclerView.addOnScrollListener(this.mScrollListener);
        RecyclerView.LayoutManager manager = this.mRv.getLayoutManager();
        if (manager instanceof GridLayoutManager) {
            GridLayoutManager gridLayoutManager = (GridLayoutManager) manager;
            final int spanSize = gridLayoutManager.getSpanCount();
            gridLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageAdapterHelper.3
                @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                public int getSpanSize(int position) {
                    int dc = PageAdapterHelper.this.spanSizeLookup != null ? PageAdapterHelper.this.spanSizeLookup.getSpanSize(position) : 1;
                    if (PageAdapterHelper.this.isShowLoadMoreViewEnable()) {
                        int totalCount = PageAdapterHelper.this.getItemCount() - 1;
                        if (PageAdapterHelper.this.ignorePageLimit || totalCount >= PageAdapterHelper.this.PAGE_LIMIT) {
                            return position == totalCount ? spanSize : dc;
                        }
                    }
                    return dc;
                }
            });
        }
    }

    public void setAdapterStateView(AdapterStateView adapterStateView) {
        this.mAdapterStateView = adapterStateView;
        adapterStateView.getView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.-$$Lambda$PageAdapterHelper$R_nv2ny4fx5BlUqSJMjo20b2vZ0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setAdapterStateView$0$PageAdapterHelper(view);
            }
        });
    }

    public /* synthetic */ void lambda$setAdapterStateView$0$PageAdapterHelper(View v) {
        AdapterStateView adapterStateView;
        if (this.mShowLoadViewEnable && (adapterStateView = this.mAdapterStateView) != null && adapterStateView.getState() != 1 && this.mAdapterStateView.getState() != 3 && !this.mNoMoreData) {
            this.mPage++;
            loadData();
        }
    }

    public AdapterStateView getAdapterStateView() {
        return this.mAdapterStateView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadData() {
        if (getData().size() >= this.PAGE_LIMIT || this.ignorePageLimit) {
            loadMoreStart();
            ArrayList<PageLoadMoreListener> arrayList = this.pageLoadMoreListenerList;
            if (arrayList != null) {
                for (PageLoadMoreListener l : arrayList) {
                    if (l != null) {
                        l.loadData(this.mPage);
                    }
                }
                return;
            }
            return;
        }
        if (getData().size() == 0) {
            pageReset();
            MryEmptyView mryEmptyView = this.mEmptyView;
            if (mryEmptyView != null) {
                mryEmptyView.showLoading();
            }
        }
        ArrayList<PageLoadMoreListener> arrayList2 = this.pageLoadMoreListenerList;
        if (arrayList2 != null) {
            for (PageLoadMoreListener l2 : arrayList2) {
                if (l2 != null) {
                    l2.loadData(this.mPage);
                }
            }
        }
    }

    private void checkShowLoadMoreState(List<T> data) {
        this.mIsRefreshing = false;
        if (data != null && data.size() > 0) {
            if (this.mPage == this.mStartPage) {
                checkIfEmpty();
            }
            if (this.mShowLoadViewEnable) {
                loadMoreFinish();
            }
        } else if (this.mPage == this.mStartPage) {
            checkIfEmpty();
        } else if (this.mShowLoadViewEnable) {
            loadMoreNoMoreData();
            int i = this.mPage;
            if (i - 1 >= this.mStartPage) {
                this.mPage = i - 1;
            }
        }
        RefreshLayout refreshLayout = this.refreshLayout;
        if (refreshLayout != null) {
            refreshLayout.finishRefresh(100);
            this.refreshLayout.finishLoadMore(100);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkIfEmpty() {
        if (this.mEmptyView != null) {
            if (getData().size() == 0) {
                this.mEmptyView.showEmpty();
            } else {
                this.mEmptyView.showContent();
            }
        }
    }

    public Context getContext() {
        WeakReference<Context> weakReference = this.mContextWeak;
        if (weakReference != null) {
            return weakReference.get();
        }
        return null;
    }

    public void setSpanSizeLookup(GridLayoutManager.SpanSizeLookup spanSizeLookup) {
        this.spanSizeLookup = spanSizeLookup;
    }

    public void addPageLoadMoreListener(PageLoadMoreListener pageLoadMoreListener) {
        if (pageLoadMoreListener != null) {
            this.pageLoadMoreListenerList.add(pageLoadMoreListener);
        }
    }

    public void removePageLoadMoreListener(PageLoadMoreListener pageLoadMoreListener) {
        if (pageLoadMoreListener != null) {
            this.pageLoadMoreListenerList.remove(pageLoadMoreListener);
        }
    }

    public void setData(List<T> data) {
        this.mData = data == null ? new ArrayList<>() : data;
        checkShowLoadMoreState(data);
        this.mAdapter.notifyDataSetChanged();
    }

    public void addData(List<T> data) {
        if (this.mPage == this.mStartPage) {
            getData().clear();
        }
        if (data != null && data.size() > 0) {
            getData().addAll(data);
        }
        checkShowLoadMoreState(data);
        this.mAdapter.notifyDataSetChanged();
    }

    public void addData(T itemData) {
        if (itemData != null) {
            getData().add(itemData);
            checkShowLoadMoreState(getData());
            this.mAdapter.notifyDataSetChanged();
        }
    }

    public boolean removeData(T itemData) {
        return getData().remove(itemData);
    }

    public T removeData(int position) {
        if (position >= 0 && position < getData().size()) {
            return getData().remove(position);
        }
        return null;
    }

    public List<T> getData() {
        List<T> list = this.mData;
        if (list != null) {
            return list;
        }
        ArrayList arrayList = new ArrayList();
        this.mData = arrayList;
        return arrayList;
    }

    public void reLoadData(boolean clearData) {
        this.mNoMoreData = false;
        pageReset();
        if (clearData) {
            getData().clear();
        }
        loadData();
    }

    public void setIgnorePageLimit(boolean ignore) {
        this.ignorePageLimit = ignore;
    }

    public void setPageLimit(int limit) {
        this.PAGE_LIMIT = limit;
    }

    public int getPage() {
        return this.mPage;
    }

    public int getStartPage() {
        return this.mStartPage;
    }

    public void pageReset() {
        this.mPage = this.mStartPage;
        AdapterStateView adapterStateView = this.mAdapterStateView;
        if (adapterStateView != null) {
            adapterStateView.reset();
        }
        this.mNoMoreData = false;
    }

    public void setStartPage(int startPage) {
        this.mStartPage = startPage;
        pageReset();
    }

    public void clearData() {
        List<T> list = this.mData;
        if (list != null) {
            list.clear();
        }
    }

    public void loadMoreReset() {
        AdapterStateView adapterStateView = this.mAdapterStateView;
        if (adapterStateView != null) {
            adapterStateView.reset();
        }
    }

    public void loadMoreStart() {
        AdapterStateView adapterStateView = this.mAdapterStateView;
        if (adapterStateView != null) {
            adapterStateView.loadMoreStart();
        }
    }

    public void loadMoreFinish() {
        this.mNoMoreData = false;
        AdapterStateView adapterStateView = this.mAdapterStateView;
        if (adapterStateView != null) {
            adapterStateView.loadMoreFinish();
        }
    }

    public void loadMoreNoMoreData() {
        this.mNoMoreData = true;
        AdapterStateView adapterStateView = this.mAdapterStateView;
        if (adapterStateView != null) {
            adapterStateView.loadMoreNoMoreData();
        }
    }

    public final void onRefresh(RefreshLayout refreshLayout) {
        if (this.refreshLayout == null) {
            this.refreshLayout = refreshLayout;
        }
        this.mIsRefreshing = true;
        reLoadData(false);
    }

    public final void onLoadMore(RefreshLayout refreshLayout) {
        if (this.refreshLayout == null) {
            this.refreshLayout = refreshLayout;
        }
        if (this.mShowLoadViewEnable) {
            throw new IllegalArgumentException("如果你要使用RefreshLayout的loadMore，请先关闭这里的loadMore，通过设置setShowLoadMoreViewEnable(false)方法进行关闭");
        }
        this.mPage++;
        loadData();
    }

    public void showLoading() {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showLoading();
        }
    }

    public void showContent() {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showContent();
        }
    }

    public void showEmpty() {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showEmpty();
        }
    }

    public void showError(CharSequence errorMsg) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showError(errorMsg);
        }
    }

    public void setEmptyViewEmptyResId(int emptyResId) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.setEmptyResId(emptyResId);
        }
    }

    public void setEmptyText(CharSequence emptyBtnText) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.setEmptyText(emptyBtnText);
        }
    }

    public void setEmptyViewErrorResId(int errorResId) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.setErrorResId(errorResId);
        }
    }

    public void setEmptyViewEmptyButtonText(CharSequence emptyButtonText) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.setEmptyBtnText(emptyButtonText);
        }
    }

    public void setEmptyViewErrorButtonText(CharSequence errorButtonText) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null) {
            mryEmptyView.setErrorBtnText(errorButtonText);
        }
    }

    public void emptyAttachView(ViewGroup rootView) {
        emptyAttachView(rootView, true);
    }

    public void emptyAttachView(ViewGroup rootView, boolean showLoading) {
        MryEmptyView mryEmptyView = this.mEmptyView;
        if (mryEmptyView != null && rootView != null) {
            mryEmptyView.attach(rootView);
            if (showLoading) {
                this.mEmptyView.showLoading();
            }
        }
    }

    public void setOnEmptyClickListener(MryEmptyView.OnEmptyOrErrorClickListener onEmptyClickListener) {
        this.mOnEmptyOrErrorClickListener = onEmptyClickListener;
    }

    public MryEmptyView getEmptyView() {
        return this.mEmptyView;
    }

    public void setShowLoadMoreViewEnable(boolean showLoadMoreView) {
        this.mShowLoadViewEnable = showLoadMoreView;
    }

    public boolean isShowLoadMoreViewEnable() {
        return this.mShowLoadViewEnable;
    }
}
