package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentStatePagerAdapter;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespTopicBean;
import com.bjz.comm.net.bean.RespTopicTypeBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.utils.RxHelper;
import com.tablayout.SlidingTabLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.decoration.TopDecorationWithSearch;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddTopicActivity extends CommFcActivity implements NotificationCenter.NotificationCenterDelegate {
    private static final String TAG = "AddTopicActivity";
    private long TopicTypeID = 0;
    private AddTopicAdapter addTopicAdapter;
    private List<AddTopicFragment> addTopicFragmentList;
    private HashMap<String, RespTopicBean.Item> cacheSelectedHashmap;
    private FrameLayout container;
    private LinearLayout content_container;
    private MryEmptyView emptyViewDialog;
    private FrameLayout fl_search_container;
    private FrameLayout fl_search_cover;
    private RecyclerListView listView;
    private MysearchAdapter mysearchAdapter;
    private String query;
    private List<RespTopicBean.Item> respTopicBeans;
    private MrySearchView searchView;
    private boolean searchWas;
    private boolean searching;
    private SlidingTabLayout tabLayout;
    private List<RespTopicTypeBean> topicTypes;
    private ViewPager vp_container;

    public AddTopicActivity(HashMap<String, RespTopicBean.Item> cacheSelectedHashmap) {
        if (cacheSelectedHashmap == null) {
            this.cacheSelectedHashmap = new HashMap<>();
        } else {
            this.cacheSelectedHashmap = cacheSelectedHashmap;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.swipeBackEnabled = false;
        this.addTopicFragmentList = new ArrayList();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.selectedTopicSuccess);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.selectedTopicSuccess);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        notifyTopicSelectChanged();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_add_topic;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        initActionBar();
        initEmptyView();
        initTablayoutAndViewPagber();
        initSearchView();
        initListView();
    }

    private void initEmptyView() {
        MryEmptyView mryEmptyView = new MryEmptyView(getParentActivity());
        this.emptyViewDialog = mryEmptyView;
        mryEmptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyViewDialog.setErrorResId(R.id.img_empty_default);
        this.emptyViewDialog.attach(this);
        this.emptyViewDialog.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$XF13WJfv__Ottm7sD_wsHX96Xu0
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initEmptyView$0$AddTopicActivity(z);
            }
        });
        this.emptyViewDialog.showLoading();
    }

    public /* synthetic */ boolean lambda$initEmptyView$0$AddTopicActivity(boolean isEmptyButton) {
        MryEmptyView mryEmptyView = this.emptyViewDialog;
        if (mryEmptyView != null) {
            mryEmptyView.showLoading();
        }
        getFcTopicList();
        return false;
    }

    private void initTablayoutAndViewPagber() {
        this.tabLayout = (SlidingTabLayout) this.fragmentView.findViewById(R.attr.tabLayout);
        this.vp_container = (ViewPager) this.fragmentView.findViewById(R.attr.vp_container);
        this.tabLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.tabLayout.setTextSelectColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tabLayout.setTextUnselectColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        ViewPager viewPager = this.vp_container;
        AddTopicAdapter addTopicAdapter = new AddTopicAdapter(this.mContext, getParentActivity().getSupportFragmentManager());
        this.addTopicAdapter = addTopicAdapter;
        viewPager.setAdapter(addTopicAdapter);
        this.tabLayout.setViewPager(this.vp_container);
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("addtopic", R.string.addtopic));
        this.actionBar.setDelegate(new ActionBar.ActionBarDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$Juz8SiP6V24CpG04QX-vCs7pS0s
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarDelegate
            public final void onSearchFieldVisibilityChanged(boolean z) {
                this.f$0.lambda$initActionBar$1$AddTopicActivity(z);
            }
        });
        MryTextView mryTextView = new MryTextView(this.mContext);
        GradientDrawable gradientDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, new int[]{this.mContext.getResources().getColor(R.color.color_87DFFA), this.mContext.getResources().getColor(R.color.color_2ECEFD)});
        mryTextView.setText(LocaleController.getString("sure", R.string.sure));
        mryTextView.setTextSize(13.0f);
        mryTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        mryTextView.setGravity(17);
        gradientDrawable.setCornerRadius(AndroidUtilities.dp(50.0f));
        gradientDrawable.setShape(0);
        mryTextView.setBackground(gradientDrawable);
        FrameLayout.LayoutParams layoutParams = LayoutHelper.createFrame(63, 30.0f);
        layoutParams.rightMargin = AndroidUtilities.dp(15.0f);
        layoutParams.topMargin = AndroidUtilities.dp(6.0f);
        this.actionBar.createMenu().addItemView(1, mryTextView, layoutParams);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AddTopicActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1 || id == 1) {
                    AddTopicActivity.this.getAccountInstance().getNotificationCenter();
                    NotificationCenter.getInstance(AddTopicActivity.this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccessToPublish, AddTopicActivity.this.cacheSelectedHashmap);
                    AddTopicActivity.this.finishFragment();
                }
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$1$AddTopicActivity(boolean visible) {
        this.actionBar.getBackButton().setVisibility(visible ? 0 : 8);
    }

    private void initListView() {
        this.container = (FrameLayout) this.fragmentView.findViewById(R.attr.container);
        this.content_container = (LinearLayout) this.fragmentView.findViewById(R.attr.content_container);
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listView);
        this.listView = recyclerListView;
        recyclerListView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.listView.setLayoutManager(new GridLayoutManager(this.mContext, 2));
        this.listView.addItemDecoration(new TopDecorationWithSearch(60, true));
        MysearchAdapter mysearchAdapter = new MysearchAdapter(this.mContext);
        this.mysearchAdapter = mysearchAdapter;
        this.listView.setAdapter(mysearchAdapter);
        this.listView.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AddTopicActivity.2
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    if (AddTopicActivity.this.searching && AddTopicActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(AddTopicActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                int off = recyclerView.computeVerticalScrollOffset();
                if (off == 0) {
                    AddTopicActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
                    AddTopicActivity.this.fl_search_container.setScrollY(off > AndroidUtilities.dp(55.0f) ? AndroidUtilities.dp(55.0f) : off);
                } else if (off > 0) {
                    AddTopicActivity.this.fl_search_container.setBackgroundColor(0);
                    AddTopicActivity.this.fl_search_container.setScrollY(off > AndroidUtilities.dp(55.0f) ? AndroidUtilities.dp(55.0f) : off);
                }
            }
        });
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$3FRAjequLcvaDDzV5iL4v8Cs4Y0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initListView$2$AddTopicActivity(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$initListView$2$AddTopicActivity(View view, int position) {
        RespTopicBean.Item selectedtopic = this.mysearchAdapter.getData().get(position);
        String key = selectedtopic.ID + "" + selectedtopic.TypeID;
        if (this.cacheSelectedHashmap.get(key) == null) {
            if (this.cacheSelectedHashmap.size() >= 3) {
                FcToastUtils.show((CharSequence) LocaleController.getString("selcetthreetopic", R.string.selcetthreetopic));
            } else {
                this.cacheSelectedHashmap.put(key, selectedtopic);
                getAccountInstance().getNotificationCenter();
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccess, new Object[0]);
            }
        } else {
            this.cacheSelectedHashmap.remove(key);
            getAccountInstance().getNotificationCenter();
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccess, new Object[0]);
        }
        this.mysearchAdapter.notifyDataSetChanged();
    }

    private void initSearchView() {
        FrameLayout frameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_search_cover);
        this.fl_search_cover = frameLayout;
        frameLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$Cz69sXsHWTsfAraDD295XaiHCAs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                AddTopicActivity.lambda$initSearchView$3(view);
            }
        });
        FrameLayout frameLayout2 = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_search_container);
        this.fl_search_container = frameLayout2;
        frameLayout2.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
        MrySearchView mrySearchView = (MrySearchView) this.fragmentView.findViewById(R.attr.searchview);
        this.searchView = mrySearchView;
        mrySearchView.setCancelTextColor(this.mContext.getResources().getColor(R.color.color_778591));
        this.searchView.setEditTextBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), Theme.getColor(Theme.key_divider), AndroidUtilities.dp(50.0f)));
        this.searchView.setHintText(LocaleController.getString("searchTopic", R.string.searchTopic));
        this.searchView.setiSearchViewDelegate(new MrySearchView.ISearchViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AddTopicActivity.3
            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onStart(boolean focus) {
                if (!focus) {
                    if (AddTopicActivity.this.actionBar.getVisibility() == 4) {
                        AddTopicActivity addTopicActivity = AddTopicActivity.this;
                        addTopicActivity.showTitle(addTopicActivity.fragmentView);
                    }
                    AddTopicActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
                    AddTopicActivity.this.fl_search_cover.setVisibility(8);
                    return;
                }
                AddTopicActivity addTopicActivity2 = AddTopicActivity.this;
                addTopicActivity2.hideTitle(addTopicActivity2.fragmentView);
                AddTopicActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                AddTopicActivity.this.fl_search_cover.setVisibility(0);
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchExpand() {
                AddTopicActivity.this.searching = true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public boolean canCollapseSearch() {
                AddTopicActivity.this.searching = false;
                AddTopicActivity.this.searchWas = false;
                AddTopicActivity.this.listView.setAdapter(AddTopicActivity.this.mysearchAdapter);
                AddTopicActivity.this.mysearchAdapter.notifyDataSetChanged();
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchCollapse() {
                AddTopicActivity.this.searching = false;
                AddTopicActivity.this.searchWas = false;
                AddTopicActivity.this.listView.setVisibility(8);
                AddTopicActivity.this.content_container.setVisibility(0);
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onTextChange(String text) {
                if (AddTopicActivity.this.mysearchAdapter != null) {
                    AddTopicActivity.this.query = text;
                    if (text.length() != 0) {
                        AddTopicActivity.this.searchWas = true;
                        AddTopicActivity.this.dosearchtopic();
                    } else if (AddTopicActivity.this.searching) {
                        AddTopicActivity.this.listView.setAdapter(AddTopicActivity.this.mysearchAdapter);
                        AddTopicActivity.this.mysearchAdapter.getData().clear();
                        AddTopicActivity.this.mysearchAdapter.notifyDataSetChanged();
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onActionSearch(String trim) {
            }
        });
    }

    static /* synthetic */ void lambda$initSearchView$3(View v) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        getFcTopicList();
    }

    private class MysearchAdapter extends PageSelectionAdapter<RespTopicBean.Item, PageHolder> {
        public MysearchAdapter(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(AddTopicActivity.this.mContext).inflate(R.layout.item_fc_topic, parent, false);
            return new PageHolder(view);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, RespTopicBean.Item item) {
            RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f));
            if (position % 2 == 0) {
                layoutParams.topMargin = AndroidUtilities.dp(15.0f);
                layoutParams.leftMargin = AndroidUtilities.dp(15.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
            } else {
                layoutParams.rightMargin = AndroidUtilities.dp(15.0f);
                layoutParams.topMargin = AndroidUtilities.dp(15.0f);
            }
            if (getItemCount() % 2 == 0) {
                if (position == getItemCount() - 1 || position == getItemCount() - 2) {
                    layoutParams.bottomMargin = AndroidUtilities.dp(15.0f);
                }
            } else if (position == getItemCount() - 1) {
                layoutParams.bottomMargin = AndroidUtilities.dp(15.0f);
            }
            holder.itemView.setLayoutParams(layoutParams);
            if (AddTopicActivity.this.cacheSelectedHashmap.get(item.ID + "" + item.TypeID) != null) {
                holder.itemView.setBackground(DrawableUtils.createLayerDrawable(AddTopicActivity.this.mContext.getResources().getColor(R.color.color_F0FCFF), AddTopicActivity.this.mContext.getResources().getColor(R.color.color_2ECEFD), 0.0f));
            } else {
                holder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            MryTextView tv_title = (MryTextView) holder.itemView.findViewById(R.attr.tv_title);
            MryTextView tv_subtitle = (MryTextView) holder.itemView.findViewById(R.attr.tv_subtitle);
            MryTextView tv_tag = (MryTextView) holder.itemView.findViewById(R.attr.tv_tag);
            tv_title.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            tv_subtitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            tv_tag.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            tv_title.setText(Html.fromHtml(String.format(LocaleController.getString("topictitle", R.string.topictitle), item.TopicName)));
            tv_subtitle.setText(item.Subtitle);
            if (item.Tag == 1) {
                tv_tag.setText(LocaleController.getString("fc_new", R.string.fc_new));
                tv_tag.setBackground(DrawableUtils.getGradientDrawable(new float[]{AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f}, AddTopicActivity.this.mContext.getResources().getColor(R.color.color_FFFD8A94), AddTopicActivity.this.mContext.getResources().getColor(R.color.color_FFFD6FCB)));
            } else if (item.Tag == 2) {
                tv_tag.setText(LocaleController.getString("fc_recommend", R.string.fc_recommend));
                tv_tag.setBackground(DrawableUtils.getGradientDrawable(new float[]{AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f}, AddTopicActivity.this.mContext.getResources().getColor(R.color.color_FF50F7FD), AddTopicActivity.this.mContext.getResources().getColor(R.color.color_FF2ED2FE)));
            } else {
                tv_tag.setVisibility(8);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter, im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageLoadMoreListener
        public void loadData(int page) {
            super.loadData(page);
            AddTopicActivity.this.getTopics(page);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dosearchtopic() {
        this.content_container.setVisibility(8);
        this.listView.setVisibility(0);
        this.fl_search_cover.setVisibility(8);
        this.mysearchAdapter.notifyDataSetChanged();
        getTopics(0);
    }

    protected void getFcTopicList() {
        Observable<BResponse<ArrayList<RespTopicTypeBean>>> observable = ApiFactory.getInstance().getApiMomentForum().getFcTopicList();
        RxHelper.getInstance().sendRequest(TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$4UbQrInREYSDf_f0WRbnXhaj_1w
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getFcTopicList$4$AddTopicActivity((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$x0gHZ4W1D_Erqtu9DG-xcZoWSLk
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getFcTopicList$5$AddTopicActivity((Throwable) obj);
            }
        });
    }

    public /* synthetic */ void lambda$getFcTopicList$4$AddTopicActivity(BResponse responseData) throws Exception {
        if (responseData != null) {
            if (responseData.isState() && responseData.Data != 0) {
                List<RespTopicTypeBean> list = (List) responseData.Data;
                this.topicTypes = list;
                for (RespTopicTypeBean topicTypes : list) {
                    this.addTopicFragmentList.add(new AddTopicFragment(topicTypes, this.cacheSelectedHashmap));
                }
                this.emptyViewDialog.showContent();
                if (this.addTopicFragmentList.size() > 0) {
                    this.addTopicAdapter.notifyDataSetChanged();
                    this.tabLayout.notifyDataSetChanged();
                    return;
                }
                return;
            }
            this.emptyViewDialog.showEmpty();
            FcToastUtils.show((CharSequence) responseData.Message);
            return;
        }
        this.emptyViewDialog.showError(LocaleController.getString("fc_request_fialed", R.string.fc_request_fialed));
        FcToastUtils.show((CharSequence) "请求失败");
    }

    public /* synthetic */ void lambda$getFcTopicList$5$AddTopicActivity(Throwable throwable) throws Exception {
        this.emptyViewDialog.showError(LocaleController.getString("fc_request_fialed", R.string.fc_request_fialed));
    }

    private class AddTopicAdapter extends FragmentStatePagerAdapter {
        private Context mContext;

        public AddTopicAdapter(Context context, FragmentManager fm) {
            super(fm);
            this.mContext = context;
        }

        @Override // androidx.fragment.app.FragmentStatePagerAdapter
        public Fragment getItem(int position) {
            if (AddTopicActivity.this.addTopicFragmentList.get(position) == null) {
                return null;
            }
            return (Fragment) AddTopicActivity.this.addTopicFragmentList.get(position);
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            if (AddTopicActivity.this.topicTypes == null) {
                return 0;
            }
            return AddTopicActivity.this.topicTypes.size();
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public CharSequence getPageTitle(int position) {
            return AddTopicActivity.this.topicTypes == null ? "" : ((RespTopicTypeBean) AddTopicActivity.this.topicTypes.get(position)).TopicTypeName;
        }
    }

    private void notifyTopicSelectChanged() {
        for (AddTopicFragment fragment : this.addTopicFragmentList) {
            fragment.setselectedItemCount(this.cacheSelectedHashmap);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getTopics(int pageNo) {
        Observable<BResponse<RespTopicBean>> observable = ApiFactory.getInstance().getApiMomentForum().getFcTopic(this.TopicTypeID, this.query, pageNo * 20, 20);
        RxHelper.getInstance().sendRequest(TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$hXftyULz0i6vFhAHWFNrKHsn1Jg
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getTopics$6$AddTopicActivity((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicActivity$SbSL6_1ch4oMcuopoD4LCw17W-Q
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getTopics$7$AddTopicActivity((Throwable) obj);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$getTopics$6$AddTopicActivity(BResponse response) throws Exception {
        if (response != null && response.isState()) {
            if (response.Data != 0) {
                List<RespTopicBean.Item> topics = ((RespTopicBean) response.Data).getTopics();
                this.respTopicBeans = topics;
                this.mysearchAdapter.addData((List) topics);
                return;
            }
            this.mysearchAdapter.showEmpty();
            return;
        }
        this.mysearchAdapter.showError(LocaleController.getString("request_fialed", R.string.fc_request_fialed));
    }

    public /* synthetic */ void lambda$getTopics$7$AddTopicActivity(Throwable throwable) throws Exception {
        this.mysearchAdapter.showError(LocaleController.getString("request_fialed", R.string.fc_request_fialed));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        getAccountInstance().getNotificationCenter();
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccessToPublish, this.cacheSelectedHashmap);
        return super.onBackPressed();
    }
}
